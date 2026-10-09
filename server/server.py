import socket
import ssl
import threading
import json
import os
import logging
from datetime import datetime

# Configuración del servidor
HOST = '0.0.0.0'
PORT = 8443
CERTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'pki', 'certs')
SERVER_CERT = os.path.join(CERTS_DIR, 'server-cert.pem')
SERVER_KEY = os.path.join(CERTS_DIR, 'server-key.pem')
CA_CERT = os.path.join(CERTS_DIR, 'ca-cert.pem')
USERS_FILE = os.path.join(os.path.dirname(__file__), 'users.json')
AUDIT_LOG = os.path.join(os.path.dirname(__file__), 'audit.log')

# Configuración de Auditoría (RS4)
logging.basicConfig(
    filename=AUDIT_LOG,
    level=logging.INFO,
    format='%(asctime)s - AUDIT - %(levelname)s - %(message)s'
)

def load_users():
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def handle_client(conn, addr, users):
    logging.info(f"Conexión TLS establecida desde {addr[0]}:{addr[1]}")
    
    try:
        # Autenticación de capa de aplicación (Usuario y Contraseña)
        # El certificado de cliente ya ha sido validado en el handshake (mTLS)
        auth_data = conn.recv(1024).decode('utf-8')
        if not auth_data:
            return
            
        try:
            credentials = json.loads(auth_data)
            username = credentials.get('username')
            password = credentials.get('password')
        except:
            conn.sendall(b"ERROR: Formato de credenciales invalido.\n")
            logging.warning(f"Intento de conexión con formato de credenciales inválido desde {addr[0]}:{addr[1]}")
            return
            
        if username in users and users[username]['password'] == password:
            conn.sendall(b"OK: Autenticacion exitosa. Tunel VPN establecido.\n")
            msg = f"Usuario '{username}' ({users[username]['role']}) autenticado correctamente desde {addr[0]}."
            print(f"[*] {msg}")
            logging.info(msg)
            
            # Bucle principal de la VPN (recepción de datos)
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                
                command = data.decode('utf-8').strip()
                if command == "LOGOUT":
                    msg_logout = f"Usuario '{username}' ha cerrado la sesion explícitamente."
                    print(f"[*] {msg_logout}")
                    logging.info(msg_logout)
                    conn.sendall(b"Sesion cerrada exitosamente. Desmontando tunel.\n")
                    break
                
                # Eco para demostración
                response = f"Servidor recibio (Cifrado): {command}\n"
                conn.sendall(response.encode('utf-8'))
                
        else:
            conn.sendall(b"ERROR: Credenciales invalidas.\n")
            msg_fail = f"Intento de acceso fallido (Credenciales inválidas) para el usuario '{username}' desde {addr[0]}."
            print(f"[!] {msg_fail}")
            logging.warning(msg_fail)
            
    except ssl.SSLError as e:
        msg_ssl = f"Error de Seguridad SSL/mTLS con {addr[0]}: {e}"
        print(f"[!] {msg_ssl}")
        logging.error(msg_ssl)
    except Exception as e:
        msg_err = f"Error de conexión con {addr[0]}: {e}"
        print(f"[!] {msg_err}")
        logging.error(msg_err)
    finally:
        logging.info(f"Cerrando conexión y desmontando túnel con {addr[0]}")
        conn.close()

def start_server():
    users = load_users()
    
    # Configuración del contexto SSL para TLS 1.3 y mTLS
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    
    # Forzar TLS 1.3 (Restringir SSLv3, TLS 1.0, TLS 1.1, TLS 1.2)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    
    # Cipher suites robustas (PFS y AEAD)
    # Nota: OpenSSL gestiona las cipher suites de TLS 1.3 automáticamente. 
    # Al forzar TLS 1.3 arriba, garantizamos que solo se usarán AEAD + PFS (ej. TLS_AES_256_GCM_SHA384).
    # context.set_ciphers('TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256')
    
    # Cargar certificado del servidor y clave privada
    context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
    
    # Configurar validación estricta de certificado de cliente (mTLS)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=CA_CERT)
    
    # Crear socket de red
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(350)  # Preparado para >300 conexiones concurrentes
    
    print(f"[*] Servidor VPN TLS escuchando en {HOST}:{PORT}")
    print("[*] Requisitos: TLS 1.3, mTLS activo, Cipher Suites robustas.")
    
    try:
        while True:
            client_sock, addr = server_socket.accept()
            # Envolver el socket con SSL
            try:
                secure_sock = context.wrap_socket(client_sock, server_side=True)
                
                # Crear un hilo por cada cliente (Modelo de concurrencia)
                client_thread = threading.Thread(target=handle_client, args=(secure_sock, addr, users))
                client_thread.daemon = True
                client_thread.start()
            except ssl.SSLError as e:
                print(f"[!] Fallo en el handshake SSL (mTLS rechazado) desde {addr}: {e}")
                client_sock.close()
                
    except KeyboardInterrupt:
        print("\n[*] Apagando el servidor VPN...")
    finally:
        server_socket.close()

if __name__ == '__main__':
    start_server()
