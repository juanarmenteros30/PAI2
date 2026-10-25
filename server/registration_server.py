"""
registration_server.py — Servidor de auto-registro de nuevos usuarios BYOD

Escucha en el puerto REG_PORT (8444) con TLS simple (sin mTLS) para que
clientes sin certificado puedan solicitar su alta.

Flujo:
  1. El cliente abre una conexión TLS (solo autentica el servidor, no el cliente).
  2. Envía un JSON:
       {"action": "register", "username": "...", "password": "...", "role": "..."}
  3. El servidor valida, crea el usuario en la BD y emite el certificado.
  4. Devuelve un JSON con el resultado:
       - Éxito:  {"ok": true,  "cert": "<PEM>", "key": "<PEM>"}
       - Error:  {"ok": false, "error": "<mensaje legible>"}

Seguridad:
  - TLS 1.3 obligatorio (igual que el servidor principal).
  - Rate-limit simple: máximo REG_MAX_REQS peticiones por IP en REG_WINDOW segundos.
  - El canal está cifrado; la clave privada del cliente viaja protegida por TLS.
  - La CA privada NUNCA abandona el servidor.
"""

import json
import logging
import os
import socket
import ssl
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(__file__))
from register_user import register          # valida + BD + genera cert

# ── Configuración ──────────────────────────────────────────────────────────────
REG_HOST     = '0.0.0.0'
REG_PORT     = 8444
CERTS_DIR    = os.path.join(os.path.dirname(__file__), '..', 'pki', 'certs')
SERVER_CERT  = os.path.join(CERTS_DIR, 'server-cert.pem')
SERVER_KEY   = os.path.join(CERTS_DIR, 'server-key.pem')
AUDIT_LOG    = os.path.join(os.path.dirname(__file__), 'audit.log')

# Rate-limit: máx 5 intentos de registro por IP cada 300 s
REG_MAX_REQS = 5
REG_WINDOW   = 300          # segundos

_reg_lock    = threading.Lock()
_reg_counts  = {}           # ip -> (count, window_start)

logger = logging.getLogger(__name__)   # usa el handler raíz configurado en server.py


# ── Helpers ────────────────────────────────────────────────────────────────────

def _rate_ok(ip: str) -> bool:
    """Devuelve True si la IP puede realizar otra petición de registro."""
    with _reg_lock:
        now = time.time()
        count, t0 = _reg_counts.get(ip, (0, now))
        if now - t0 > REG_WINDOW:          # ventana caducada → reiniciar
            count, t0 = 0, now
        if count >= REG_MAX_REQS:
            return False
        _reg_counts[ip] = (count + 1, t0)
        return True


def _send_json(conn: ssl.SSLSocket, payload: dict) -> None:
    conn.sendall(json.dumps(payload, ensure_ascii=False).encode('utf-8'))


def _read_cert_pem(username: str) -> tuple[str, str]:
    """Lee el cert y la clave recién generados y los devuelve como strings PEM."""
    cert_path = os.path.join(CERTS_DIR, f"{username}-cert.pem")
    key_path  = os.path.join(CERTS_DIR, f"{username}-key.pem")
    with open(cert_path, 'r') as f:
        cert_pem = f.read()
    with open(key_path, 'r') as f:
        key_pem = f.read()
    return cert_pem, key_pem


# ── Gestión de cada conexión ───────────────────────────────────────────────────

def _handle_registration(conn: ssl.SSLSocket, ip: str) -> None:
    conn.settimeout(15)
    try:
        raw = conn.recv(4096).decode('utf-8')
        if not raw:
            return

        try:
            req = json.loads(raw)
        except json.JSONDecodeError:
            _send_json(conn, {"ok": False, "error": "JSON inválido."})
            return

        if req.get("action") != "register":
            _send_json(conn, {"ok": False, "error": "Acción desconocida."})
            return

        username = str(req.get("username", "")).strip()
        password = str(req.get("password", ""))
        role     = str(req.get("role", "")).strip()

        # Rate-limit por IP
        if not _rate_ok(ip):
            _send_json(conn, {"ok": False,
                              "error": "Demasiados intentos de registro. Espera unos minutos."})
            logger.warning(f"[REGISTRO] Rate-limit alcanzado para IP {ip}")
            return

        logger.info(f"[REGISTRO] Solicitud de alta para '{username}' desde {ip}")

        # Delegar en register() — valida + BD + cert (con rollback atómico)
        try:
            register(username, password, role)
        except ValueError as exc:
            _send_json(conn, {"ok": False, "error": str(exc)})
            logger.warning(f"[REGISTRO] Fallo para '{username}' desde {ip}: {exc}")
            return

        # Éxito: leer el cert y la clave generados y enviarlos al cliente
        cert_pem, key_pem = _read_cert_pem(username)
        _send_json(conn, {"ok": True, "cert": cert_pem, "key": key_pem})
        logger.info(f"[REGISTRO] Usuario '{username}' (rol: {role}) registrado desde {ip}")

    except socket.timeout:
        logger.warning(f"[REGISTRO] Timeout leyendo petición desde {ip}")
    except Exception as exc:
        logger.error(f"[REGISTRO] Error inesperado con {ip}: {exc}")
        try:
            _send_json(conn, {"ok": False, "error": "Error interno del servidor."})
        except Exception:
            pass
    finally:
        try:
            conn.unwrap()
        except Exception:
            pass
        conn.close()


# ── Servidor ───────────────────────────────────────────────────────────────────

def _build_context() -> ssl.SSLContext:
    """Contexto TLS 1.3 sin verificación de certificado de cliente."""
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode     = ssl.CERT_NONE          # sin mTLS: el cliente no tiene cert todavía
    ctx.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
    return ctx


def start_registration_server() -> None:
    """
    Arranca el servidor de registro. Diseñado para ejecutarse en un hilo daemon
    junto al servidor VPN principal.
    """
    if not os.path.exists(SERVER_CERT) or not os.path.exists(SERVER_KEY):
        logger.error("[REGISTRO] Faltan certificados del servidor; el servicio de registro no arranca.")
        return

    ctx = _build_context()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if os.name == 'nt' and hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    else:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((REG_HOST, REG_PORT))
    srv.listen(50)

    print(f"[*] Servidor de REGISTRO TLS escuchando en {REG_HOST}:{REG_PORT}")
    logger.info(f"Servidor de registro arrancado en {REG_HOST}:{REG_PORT}")

    while True:
        try:
            raw_conn, addr = srv.accept()
            ip = addr[0]
            try:
                raw_conn.settimeout(10)
                conn = ctx.wrap_socket(raw_conn, server_side=True)
            except (ssl.SSLError, OSError) as exc:
                logger.warning(f"[REGISTRO] Handshake TLS fallido desde {ip}: {exc}")
                raw_conn.close()
                continue
            threading.Thread(
                target=_handle_registration, args=(conn, ip), daemon=True
            ).start()
        except Exception as exc:
            logger.error(f"[REGISTRO] Error en accept(): {exc}")
            time.sleep(0.1)
