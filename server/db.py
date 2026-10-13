"""
db.py — Gestión de la base de datos de usuarios (SQLite + HMAC-SHA256 + Salt)

Esquema de seguridad:
  - Cada usuario tiene un salt aleatorio de 32 bytes (os.urandom).
  - La contraseña se almacena como HMAC-SHA256(salt || password) en hex.
  - Nunca se guarda la contraseña en claro.
"""

import sqlite3
import hmac
import hashlib
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'users.db')


def _get_connection() -> sqlite3.Connection:
    """Devuelve una conexión a la base de datos SQLite."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Crea la tabla de usuarios si no existe."""
    with _get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                salt     TEXT NOT NULL,
                password_hmac TEXT NOT NULL,
                role     TEXT NOT NULL
            )
        """)
        conn.commit()


def _compute_hmac(salt_hex: str, password: str) -> str:
    """
    Calcula HMAC-SHA256 usando el salt (en hex) y la contraseña.

    La clave del HMAC es el salt en bytes, y el mensaje es la contraseña
    codificada en UTF-8.  Se usa SHA-256 como función de hash.

    Parámetros
    ----------
    salt_hex : str
        Salt de 32 bytes representado como cadena hexadecimal (64 chars).
    password : str
        Contraseña en claro proporcionada por el usuario.

    Retorna
    -------
    str
        Digest HMAC-SHA256 en formato hexadecimal.
    """
    salt_bytes = bytes.fromhex(salt_hex)
    return hmac.new(salt_bytes, password.encode('utf-8'), hashlib.sha256).hexdigest()


def add_user(username: str, password: str, role: str) -> None:
    """
    Registra un nuevo usuario en la base de datos.

    Genera un salt criptográficamente seguro (os.urandom(32)) y almacena
    el HMAC-SHA256 de la contraseña —nunca la contraseña en claro—.

    Parámetros
    ----------
    username : str
        Nombre de usuario único.
    password : str
        Contraseña en claro (se descarta tras calcular el HMAC).
    role : str
        Rol del usuario (PDI, PAS, Investigadores, etc.).

    Lanza
    -----
    ValueError
        Si el usuario ya existe en la base de datos.
    """
    salt_hex = os.urandom(32).hex()          # 32 bytes → 64 chars hex
    password_hmac = _compute_hmac(salt_hex, password)

    with _get_connection() as conn:
        try:
            conn.execute(
                "INSERT INTO users (username, salt, password_hmac, role) VALUES (?, ?, ?, ?)",
                (username, salt_hex, password_hmac, role)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            raise ValueError(f"El usuario '{username}' ya existe en la base de datos.")


def verify_user(username: str, password: str) -> dict | None:
    """
    Verifica las credenciales de un usuario de forma segura (comparación
    en tiempo constante mediante hmac.compare_digest).

    Parámetros
    ----------
    username : str
        Nombre de usuario.
    password : str
        Contraseña en claro a verificar.

    Retorna
    -------
    dict | None
        Diccionario con las claves 'username' y 'role' si las credenciales
        son correctas; None en caso contrario.
    """
    with _get_connection() as conn:
        row = conn.execute(
            "SELECT salt, password_hmac, role FROM users WHERE username = ?",
            (username,)
        ).fetchone()

    if row is None:
        return None

    expected_hmac = _compute_hmac(row['salt'], password)

    # Comparación en tiempo constante para evitar ataques de timing
    if hmac.compare_digest(expected_hmac, row['password_hmac']):
        return {'username': username, 'role': row['role']}
    return None


def user_exists(username: str) -> bool:
    """Comprueba si un nombre de usuario ya está registrado."""
    with _get_connection() as conn:
        row = conn.execute(
            "SELECT 1 FROM users WHERE username = ?", (username,)
        ).fetchone()
    return row is not None
