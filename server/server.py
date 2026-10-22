import socket
import ssl
import threading
import json
import os
import sys
import logging
import re
import time

# Añadir directorio padre al path para importar db
sys.path.insert(0, os.path.dirname(__file__))
from db import init_db, verify_user

# Configuración del servidor
HOST = '0.0.0.0'
PORT = 8443
CERTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'pki', 'certs')
SERVER_CERT = os.path.join(CERTS_DIR, 'server-cert.pem')
SERVER_KEY = os.path.join(CERTS_DIR, 'server-key.pem')
CA_CERT = os.path.join(CERTS_DIR, 'ca-cert.pem')
AUDIT_LOG = os.path.join(os.path.dirname(__file__), 'audit.log')

HANDSHAKE_TIMEOUT = 10      # s para completar el handshake mTLS
IDLE_TIMEOUT = 300          # s de inactividad en sesión
ALLOWED_CIPHERS = {"TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"}
MAX_FAILS, LOCK_SECONDS = 5, 60
MAX_CONNECTIONS = 500       # tope de hilos simultáneos (protege frente a DoS); >300 exigidos
_slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
_fails = {}                 # (ip, usuario) -> (nº fallos, instante primer fallo)
_fails_lock = threading.Lock()

def clean(value):
    """Evita log injection (saltos de línea) y limita longitud."""
    return re.sub(r'[\r\n\t]', '_', str(value))[:64]

def is_locked(key):
    with _fails_lock:
        n, t0 = _fails.get(key, (0, 0))
        if n >= MAX_FAILS and time.time() - t0 < LOCK_SECONDS:
            return True
        if n >= MAX_FAILS:
            clear_fails(key)
        return False

def register_fail(key):
    with _fails_lock:
        now = time.time()
        if len(_fails) > 10_000:            # evita crecimiento ilimitado de la tabla
            for k in [k for k, (_, t) in _fails.items() if now - t >= LOCK_SECONDS]:
                del _fails[k]
        n, t0 = _fails.get(key, (0, now))
        _fails[key] = (n + 1, t0)

def clear_fails(key):
    with _fails_lock:
        _fails.pop(key, None)

def say(msg):
    """print que nunca rompe un hilo (p. ej. consolas Windows con codificación limitada)."""
    try:
        print(msg)
    except Exception:
        pass

# Configuración de Auditoría (RS4)
logging.basicConfig(
    filename=AUDIT_LOG,
    level=logging.INFO,
    format='%(asctime)s - AUDIT - %(levelname)s - %(message)s',
    encoding='utf-8'
)

def handle_client(raw_conn, addr, context):
    ip = addr[0]
    # 1) Handshake mTLS DENTRO del hilo y con timeout (un cliente lento no bloquea el accept)
    try:
        raw_conn.settimeout(HANDSHAKE_TIMEOUT)
        conn = context.wrap_socket(raw_conn, server_side=True)
    except (ssl.SSLError, OSError) as e:
        msg = f"Handshake mTLS RECHAZADO desde {ip}:{addr[1]}: {clean(e)}"
        logging.warning(msg)
        raw_conn.close()
        say(f"[!] {msg}")
        return

    try:
        cipher_name, tls_version, key_bits = conn.cipher()
        # 2) RS2: aceptar solo las suites exigidas (Python no permite fijarlas en TLS 1.3)
        if cipher_name not in ALLOWED_CIPHERS:
            logging.warning(f"Cipher no permitido ({cipher_name}) desde {ip}; conexión cerrada")
            return

        # 3) CN del certificado de cliente validado por la CA
        subject = conn.getpeercert()["subject"]
        cert_cn = next((v for rdn in subject for k, v in rdn if k == "commonName"), None)
        logging.info(
            f"Conexión TLS establecida desde {ip}:{addr[1]} | CN cert: {clean(cert_cn)} | "
            f"Cipher: {cipher_name} | Versión: {tls_version} | Bits: {key_bits}"
        )
        say(f"[*] {ip} CN={cert_cn} cipher={cipher_name} ({tls_version}, {key_bits} bits)")

        auth_data = conn.recv(1024).decode('utf-8')
        if not auth_data:
            return
        try:
            credentials = json.loads(auth_data)
            username = credentials['username']
            password = credentials['password']
            if not isinstance(username, str) or not isinstance(password, str):
                raise ValueError
        except Exception:
            conn.sendall(b"ERROR: Formato de credenciales invalido.\n")
            logging.warning(f"Credenciales con formato inválido desde {ip}")
            return

        key = (ip, username)
        if is_locked(key):
            conn.sendall(b"ERROR: Cuenta bloqueada temporalmente.\n")
            logging.warning(f"Intento sobre cuenta bloqueada '{clean(username)}' desde {ip}")
            return

        # 4) Ligar certificado <-> usuario: el CN del cert debe ser el usuario que hace login
        user_info = verify_user(username, password)
        if user_info and cert_cn != username:
            logging.warning(
                f"SUPLANTACIÓN: cert CN='{clean(cert_cn)}' intenta entrar como '{clean(username)}' desde {ip}"
            )
            user_info = None

        if not user_info:
            register_fail(key)
            conn.sendall(b"ERROR: Credenciales invalidas.\n")
            msg_fail = f"Acceso fallido para '{clean(username)}' (cert '{clean(cert_cn)}') desde {ip}"
            say(f"[!] {msg_fail}")
            logging.warning(msg_fail)
            return

        _fails.pop(key, None)
        conn.sendall(b"OK: Autenticacion exitosa. Tunel VPN establecido.\n")
        logging.info(f"Usuario '{clean(username)}' ({user_info['role']}) autenticado desde {ip}")

        conn.settimeout(IDLE_TIMEOUT)
        while True:
            data = conn.recv(4096)
            if not data:
                break
            command = data.decode('utf-8').strip()
            if command == "LOGOUT":
                logging.info(f"Usuario '{clean(username)}' cerró la sesión explícitamente.")
                conn.sendall(b"Sesion cerrada exitosamente. Desmontando tunel.\n")
                break
            conn.sendall(f"Servidor recibio (Cifrado): {command}\n".encode('utf-8'))

    except socket.timeout:
        logging.warning(f"Timeout de inactividad con {ip}")
    except ssl.SSLError as e:
        logging.error(f"Error SSL/mTLS con {ip}: {clean(e)}")
    except Exception as e:
        logging.error(f"Error de conexión con {ip}: {clean(e)}")
    finally:
        logging.info(f"Cerrando conexión y desmontando túnel con {ip}")
        try:
            conn.unwrap()       # envía close_notify (cierre TLS ordenado)
        except Exception:
            pass
        conn.close()

def serve(client_sock, addr, context):
    """Atiende una conexión y libera su hueco al terminar."""
    try:
        handle_client(client_sock, addr, context)
    finally:
        _slots.release()

def start_server():
    missing = [p for p in (SERVER_CERT, SERVER_KEY, CA_CERT) if not os.path.exists(p)]
    if missing:
        print("[!] Faltan certificados:")
        for p in missing:
            print(f"    - {os.path.normpath(p)}")
        print("    Genera la PKI primero:  python pki/generate_pki.py")
        sys.exit(1)

    # Inicializar base de datos SQLite (crea la tabla si no existe)
    init_db()
    print("[*] Base de datos SQLite de usuarios inicializada.")

    # Configuración del contexto SSL para TLS 1.3 y mTLS
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

    # Forzar TLS 1.3 (Restringir SSLv3, TLS 1.0, TLS 1.1, TLS 1.2)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3

    # Cipher suites robustas (PFS y AEAD)
    # Nota: OpenSSL gestiona las cipher suites de TLS 1.3 automáticamente.
    # Al forzar TLS 1.3 arriba, garantizamos que solo se usarán AEAD + PFS
    # (ej. TLS_AES_256_GCM_SHA384 o TLS_CHACHA20_POLY1305_SHA256).
    # context.set_ciphers('TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256')

    # Cargar certificado del servidor y clave privada
    context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)

    # Configurar validación estricta de certificado de cliente (mTLS)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=CA_CERT)

    # Crear socket de red
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if os.name == 'nt' and hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
        # En Windows SO_REUSEADDR permite que OTRO proceso use el mismo puerto: se evita
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    else:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(350)  # Preparado para >300 conexiones concurrentes

    print(f"[*] Servidor VPN TLS escuchando en {HOST}:{PORT}")
    print("[*] Requisitos: TLS 1.3, mTLS activo, Cipher Suites robustas.")
    print("[*] Autenticación: certificado de cliente + SQLite (PBKDF2-HMAC-SHA256 + Salt).")

    try:
        while True:
            try:
                client_sock, addr = server_socket.accept()
            except OSError as e:                      # p. ej. fallo transitorio de accept()
                logging.error(f"Error en accept(): {clean(e)}")
                time.sleep(0.1)
                continue
            if not _slots.acquire(blocking=False):
                logging.warning(f"Límite de {MAX_CONNECTIONS} conexiones alcanzado; rechazando {addr[0]}")
                client_sock.close()
                continue
            threading.Thread(
                target=serve, args=(client_sock, addr, context), daemon=True
            ).start()

    except KeyboardInterrupt:
        print("\n[*] Apagando el servidor VPN...")
    finally:
        server_socket.close()

if __name__ == '__main__':
    start_server()
