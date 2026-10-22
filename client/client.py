import argparse
import getpass
import json
import os
import socket
import ssl
import sys

# Configuración por defecto
HOST = 'localhost'
PORT = 8443
CONNECT_TIMEOUT = 10
CERTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'pki', 'certs')
CA_CERT = os.path.join(CERTS_DIR, 'ca-cert.pem')


def start_client(username, password, port=PORT):
    client_cert = os.path.join(CERTS_DIR, f"{username}-cert.pem")
    client_key = os.path.join(CERTS_DIR, f"{username}-key.pem")

    if not os.path.exists(CA_CERT):
        print("[!] No se encuentra la CA (pki/certs/ca-cert.pem). Ejecuta pki/generate_pki.py")
        sys.exit(1)
    if not os.path.exists(client_cert) or not os.path.exists(client_key):
        print(f"[!] Certificados para el usuario '{username}' no encontrados.")
        print("Asegurate de generar los certificados con pki/generate_pki.py")
        sys.exit(1)

    # Configuración del contexto SSL
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)

    # Forzar TLS 1.3
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3

    # Cargar certificado y clave del cliente para autenticación mutua (mTLS)
    context.load_cert_chain(certfile=client_cert, keyfile=client_key)

    secure_sock = None
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.settimeout(CONNECT_TIMEOUT)      # conexión + handshake no se quedan colgados

    print(f"[*] Conectando a {HOST}:{port}...")

    try:
        # Establecer túnel TLS seguro
        secure_sock = context.wrap_socket(client_socket, server_hostname=HOST)
        secure_sock.connect((HOST, port))

        print(f"[*] Handshake mTLS exitoso. Cifrado: {secure_sock.cipher()}")

        # Enviar credenciales de capa de aplicación
        credentials = {"username": username, "password": password}
        secure_sock.sendall(json.dumps(credentials).encode('utf-8'))

        # Recibir respuesta de autenticación
        auth_response = secure_sock.recv(1024).decode('utf-8', errors='replace')
        print(f"[SERVIDOR] {auth_response.strip()}")

        if auth_response.startswith("OK"):
            secure_sock.settimeout(None)           # sesión interactiva: sin timeout
            print("\n--- TUNEL VPN ESTABLECIDO ---")
            print("Escribe tus mensajes. Escribe 'LOGOUT' para cerrar la sesión de forma segura.")

            while True:
                msg = input("VPN> ")
                if not msg:
                    continue

                secure_sock.sendall(msg.encode('utf-8'))

                response = secure_sock.recv(1024).decode('utf-8', errors='replace')
                if not response:
                    print("[!] El servidor cerró la conexión.")
                    break
                print(f"[SERVIDOR] {response.strip()}")
                if msg == "LOGOUT":
                    break

    except ssl.SSLError as e:
        print(f"[!] Error de SSL (posible fallo de mTLS): {e}")
    except (EOFError, KeyboardInterrupt):
        print("\n[*] Interrumpido por el usuario.")
    except Exception as e:
        print(f"[!] Error de conexión: {e}")
    finally:
        print("[*] Desmontando el túnel seguro y cerrando conexión.")
        if secure_sock:
            try:
                secure_sock.settimeout(2)
                secure_sock.unwrap()      # close_notify: cierre TLS ordenado
            except Exception:
                pass
            secure_sock.close()
        else:
            client_socket.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Cliente VPN BYODSEC (TLS 1.3 + mTLS)")
    parser.add_argument("-u", "--user", required=True, help="Nombre de usuario (ej. pdi_user)")
    parser.add_argument("-p", "--password",
                        help="Contraseña (si se omite se pide por teclado, sin mostrarla)")
    parser.add_argument("--port", type=int, default=PORT, help="Puerto del servidor (def. 8443)")
    args = parser.parse_args()

    password = args.password if args.password is not None else getpass.getpass("Contraseña: ")
    start_client(args.user, password, args.port)
