"""
db.py — Gestión de la base de datos de usuarios (SQLite + PBKDF2-HMAC-SHA256 + Salt)

Esquema de seguridad:
  - Cada usuario tiene un salt aleatorio de 32 bytes (os.urandom).
  - La contraseña se almacena derivada con PBKDF2-HMAC-SHA256 (salt, KDF_ITERATIONS
    iteraciones) en hex. Nunca se guarda la contraseña en claro.
  - La columna se llama `password_hmac` por compatibilidad con la BD ya creada;
    contiene la clave derivada con PBKDF2.
  - La verificación gasta el mismo tiempo exista o no el usuario (evita enumerar usuarios).
"""
from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
from contextlib import contextmanager

KDF_ITERATIONS = 200_000

DB_PATH = os.path.join(os.path.dirname(__file__), 'users.db')

# Salt falso para igualar tiempos cuando el usuario no existe
_DUMMY_SALT = os.urandom(32).hex()


@contextmanager
def _get_connection():
    """Conexión SQLite que hace commit/rollback y SIEMPRE se cierra al salir."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        with conn:
            yield conn
    finally:
        conn.close()


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


def _compute_hmac(salt_hex: str, password: str) -> str:
    """
    Deriva la clave de la contraseña con PBKDF2-HMAC-SHA256 (KDF lento) usando
    el salt (en hex) y KDF_ITERATIONS iteraciones. Devuelve el resultado en hex.
    """
    return hashlib.pbkdf2_hmac(
        'sha256', password.encode('utf-8'), bytes.fromhex(salt_hex), KDF_ITERATIONS
    ).hex()


def add_user(username: str, password: str, role: str) -> None:
    """
    Registra un nuevo usuario. Genera un salt criptográficamente seguro
    (os.urandom(32)) y guarda la clave derivada, nunca la contraseña en claro.

    Lanza ValueError si el usuario ya existe.
    """
    salt_hex = os.urandom(32).hex()          # 32 bytes → 64 chars hex
    derived = _compute_hmac(salt_hex, password)

    try:
        with _get_connection() as conn:
            conn.execute(
                "INSERT INTO users (username, salt, password_hmac, role) VALUES (?, ?, ?, ?)",
                (username, salt_hex, derived, role)
            )
    except sqlite3.IntegrityError:
        raise ValueError(f"El usuario '{username}' ya existe en la base de datos.")


def verify_user(username: str, password: str) -> dict | None:
    """
    Verifica las credenciales (comparación en tiempo constante con
    hmac.compare_digest). Devuelve {'username', 'role'} o None.

    Si el usuario no existe también se ejecuta el KDF con un salt falso, para que
    el tiempo de respuesta no revele qué usuarios existen.
    """
    if not isinstance(username, str) or not isinstance(password, str):
        return None

    with _get_connection() as conn:
        row = conn.execute(
            "SELECT salt, password_hmac, role FROM users WHERE username = ?",
            (username,)
        ).fetchone()

    if row is None:
        _compute_hmac(_DUMMY_SALT, password)
        return None

    expected = _compute_hmac(row['salt'], password)
    if hmac.compare_digest(expected, row['password_hmac']):
        return {'username': username, 'role': row['role']}
    return None


def user_exists(username: str) -> bool:
    """Comprueba si un nombre de usuario ya está registrado."""
    with _get_connection() as conn:
        row = conn.execute(
            "SELECT 1 FROM users WHERE username = ?", (username,)
        ).fetchone()
    return row is not None


def delete_user(username: str) -> None:
    """Elimina un usuario (rollback del registro si falla la emisión del certificado)."""
    with _get_connection() as conn:
        conn.execute("DELETE FROM users WHERE username = ?", (username,))
