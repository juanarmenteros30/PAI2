import json
import os
import sys

# Importar funciones de generación de PKI
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from pki.generate_pki import generate_cert
from cryptography import x509
from cryptography.hazmat.primitives import serialization

USERS_FILE = os.path.join(os.path.dirname(__file__), 'users.json')
CERTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'pki', 'certs')
CA_CERT_PATH = os.path.join(CERTS_DIR, 'ca-cert.pem')
CA_KEY_PATH = os.path.join(CERTS_DIR, 'ca-key.pem')

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def register_new_user():
    print("=== REGISTRO DE NUEVO USUARIO BYOD (RF1) ===")
    username = input("Nombre de usuario (ej. jdoe): ").strip()
    if not username:
        print("Error: El nombre de usuario no puede estar vacío.")
        return
        
    users = load_users()
    if username in users:
        print(f"Error: El usuario '{username}' ya existe.")
        return
        
    password = input("Contraseña corporativa: ").strip()
    role = input("Rol (PDI, PAS, Estudiante, etc.): ").strip()
    
    # 1. Emparejamiento de Dispositivo / Emisión de Certificado (PKI)
    print(f"\n[*] Solicitando emisión de certificado digital para '{username}'...")
    
    if not os.path.exists(CA_CERT_PATH) or not os.path.exists(CA_KEY_PATH):
        print("[!] Error: No se encuentra la CA Corporativa. Ejecuta pki/generate_pki.py primero.")
        return
        
    with open(CA_CERT_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
        
    with open(CA_KEY_PATH, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
        
    generate_cert(CERTS_DIR, username, ca_key, ca_cert, is_server=False)
    
    # 2. Guardar credenciales en el sistema (Inmutabilidad del registro principal)
    users[username] = {
        "password": password,
        "role": role
    }
    save_users(users)
    
    print("\n✅ USUARIO REGISTRADO CON ÉXITO")
    print(f"  - Credenciales guardadas.")
    print(f"  - Certificado de cliente generado: {username}-cert.pem")
    print(f"  - Llave privada generada: {username}-key.pem")
    print("\nEl usuario ya puede iniciar sesión desde el portal VPN.")

if __name__ == '__main__':
    register_new_user()
