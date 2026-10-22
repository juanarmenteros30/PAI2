import getpass
import os
import re
import sys

# Importar funciones de generación de PKI
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from pki.generate_pki import generate_cert
from cryptography import x509
from cryptography.hazmat.primitives import serialization

# Importar módulo de base de datos (PBKDF2 + Salt)
sys.path.insert(0, os.path.dirname(__file__))
from db import init_db, add_user, user_exists, delete_user

CERTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'pki', 'certs')
CA_CERT_PATH = os.path.join(CERTS_DIR, 'ca-cert.pem')
CA_KEY_PATH = os.path.join(CERTS_DIR, 'ca-key.pem')
RESERVED = {'ca', 'server'}
USERNAME_RE = re.compile(r"[a-z0-9_]{3,32}")
MIN_PASSWORD_LEN = 8


def register(username: str, password: str, role: str) -> None:
    """
    Registra un usuario BYOD: valida los datos, lo guarda en la BD y emite su
    certificado de cliente. Si falla la emisión del certificado, revierte el registro.
    Lanza ValueError con un mensaje legible si algo no es válido.
    """
    init_db()

    if not USERNAME_RE.fullmatch(username) or username in RESERVED:
        raise ValueError("usuario inválido (3-32 caracteres a-z, 0-9, _; no 'ca' ni 'server').")
    if len(password) < MIN_PASSWORD_LEN:
        raise ValueError(f"la contraseña debe tener al menos {MIN_PASSWORD_LEN} caracteres.")
    role = role.strip()
    if not role or len(role) > 32:
        raise ValueError("el rol no puede estar vacío ni superar 32 caracteres.")
    if not os.path.exists(CA_CERT_PATH) or not os.path.exists(CA_KEY_PATH):
        raise ValueError("no se encuentra la CA corporativa. Ejecuta pki/generate_pki.py primero.")
    if user_exists(username):
        raise ValueError(f"el usuario '{username}' ya existe.")

    cert_path = os.path.join(CERTS_DIR, f"{username}-cert.pem")
    key_path = os.path.join(CERTS_DIR, f"{username}-key.pem")
    if os.path.exists(cert_path) or os.path.exists(key_path):
        raise ValueError(f"ya existe un certificado para '{username}'; no se sobrescribe.")

    with open(CA_CERT_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    with open(CA_KEY_PATH, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    # Primero la BD y luego el certificado; si falla, rollback completo
    add_user(username, password, role)
    try:
        generate_cert(CERTS_DIR, username, ca_key, ca_cert, is_server=False)
    except Exception as e:
        delete_user(username)
        for p in (cert_path, key_path):
            if os.path.exists(p):
                os.remove(p)
        raise ValueError(f"falló la emisión del certificado, registro revertido: {e}")


def register_new_user():
    print("=== REGISTRO DE NUEVO USUARIO BYOD (RF1) ===")

    username = input("Nombre de usuario (ej. jdoe): ").strip()
    password = getpass.getpass("Contraseña corporativa: ")
    if getpass.getpass("Repite la contraseña: ") != password:
        print("Error: las contraseñas no coinciden.")
        return
    role = input("Rol (PDI, PAS, Estudiante, etc.): ").strip()

    print(f"\n[*] Solicitando emisión de certificado digital para '{username}'...")
    try:
        register(username, password, role)
    except ValueError as e:
        print(f"[!] Error: {e}")
        return

    print("\n[OK] USUARIO REGISTRADO CON ÉXITO")
    print("  - Credenciales almacenadas con PBKDF2-HMAC-SHA256 + Salt en SQLite.")
    print(f"  - Certificado de cliente generado: {username}-cert.pem")
    print(f"  - Llave privada generada: {username}-key.pem")
    print("\nEl usuario ya puede iniciar sesión desde el portal VPN.")


if __name__ == '__main__':
    register_new_user()
