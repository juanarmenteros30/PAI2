"""
seed_users.py — Crea (si no existen) los usuarios precargados de la práctica.

Es idempotente: si el usuario ya existe no se toca. Sirve para dejar el sistema
listo en una máquina nueva o si se borra users.db.   Uso:  python server/seed_users.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from db import init_db, add_user, user_exists

# Credenciales de DEMO de la práctica (los certificados los genera pki/generate_pki.py)
PRELOADED = [
    ("pdi_user", "pdi_password123", "PDI"),
    ("pas_user", "pas_password123", "PAS"),
    ("inv_user", "inv_password123", "Investigadores"),
]


def seed():
    init_db()
    created = []
    for username, password, role in PRELOADED:
        if not user_exists(username):
            add_user(username, password, role)
            created.append(username)
    return created


if __name__ == '__main__':
    created = seed()
    print(f"[*] Usuarios creados: {', '.join(created)}" if created
          else "[*] Los usuarios precargados ya existían; no se ha cambiado nada.")
