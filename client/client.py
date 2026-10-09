import socket
import ssl
import json
import os
import argparse
import sys

# Configuración por defecto
HOST = 'localhost'
PORT = 8443
CERTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'pki', 'certs')
CA_CERT = os.path.join(CERTS_DIR, 'ca-cert.pem')

def start_client(username, password):
    client_cert = os.path.join(CERTS_DIR, f"{username}-cert.pem")
    client_key = os.path.join(CERTS_DIR, f"{username}-key.pem")
    
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
    
    # Crear socket de red
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    print(f"[*] Conectando a {HOST}:{PORT}...")
    
    try:
        # Establecer túnel TLS seguro
        secure_sock = context.wrap_socket(client_socket, server_hostname=HOST)
        secure_sock.connect((HOST, PORT))
        
        print(f"[*] Handshake mTLS exitoso. Cifrado: {secure_sock.cipher()}")
        
        # Enviar credenciales de capa de aplicación
        credentials = {
            "username": username,
            "password": password
        }
        secure_sock.sendall(json.dumps(credentials).encode('utf-8'))
        
        # Recibir respuesta de autenticación
        auth_response = secure_sock.recv(1024).decode('utf-8')
        print(f"[SERVIDOR] {auth_response.strip()}")
        
        if "OK" in auth_response:
            print("\n--- TUNEL VPN ESTABLECIDO ---")
            print("Escribe tus mensajes. Escribe 'LOGOUT' para cerrar la sesión de forma segura.")
            
            while True:
                msg = input("VPN> ")
                if not msg:
                    continue
                    
                secure_sock.sendall(msg.encode('utf-8'))
                
                if msg == "LOGOUT":
                    response = secure_sock.recv(1024).decode('utf-8')
                    print(f"[SERVIDOR] {response.strip()}")
                    break
                    
                response = secure_sock.recv(1024).decode('utf-8')
                print(f"[SERVIDOR] {response.strip()}")
                
    except ssl.SSLError as e:
        print(f"[!] Error de SSL (posible fallo de mTLS): {e}")
    except Exception as e:
        print(f"[!] Error de conexión: {e}")
    finally:
        print("[*] Desmontando el túnel seguro y cerrando conexión.")
        client_socket.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Cliente VPN BYODSEC (TLS 1.3 + mTLS)")
    parser.add_argument("-u", "--user", required=True, help="Nombre de usuario (ej. pdi_user)")
    parser.add_argument("-p", "--password", required=True, help="Contraseña del usuario")
    args = parser.parse_args()
    
    start_client(args.user, args.password)
