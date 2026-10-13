"""
migrate_users.py — Migración única de users.json → users.db (SQLite + HMAC)

Ejecutar UNA SOLA VEZ después de clonar/actualizar el proyecto:
    python server/migrate_users.py

El script lee users.json, registra cada usuario en SQLite con HMAC-SHA256 + Salt
y, si la migración es exitosa, renombra users.json a users.json.migrated
(no lo elimina, por si necesitas hacer rollback manual).
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from db import init_db, add_user, user_exists

USERS_FILE = os.path.join(os.path.dirname(__file__), 'users.json')


def migrate():
    if not os.path.exists(USERS_FILE):
        print("[!] No se encontró users.json. Nada que migrar.")
        return

    with open(USERS_FILE, 'r') as f:
        users = json.load(f)

    init_db()
    print(f"[*] Migrando {len(users)} usuario(s) de users.json -> SQLite (HMAC-SHA256 + Salt)...\n")

    ok = 0
    skip = 0
    for username, data in users.items():
        password = data.get('password', '')
        role = data.get('role', 'Desconocido')

        if user_exists(username):
            print(f"  [~] '{username}' ya existe en la BD — omitido.")
            skip += 1
            continue

        add_user(username, password, role)
        print(f"  [OK] '{username}' ({role}) migrado correctamente.")
        ok += 1

    print(f"\n[*] Migracion completada: {ok} migrados, {skip} omitidos.")

    # Renombrar el JSON para evitar que se use accidentalmente
    migrated_path = USERS_FILE + '.migrated'
    os.rename(USERS_FILE, migrated_path)
    print(f"[*] users.json renombrado a '{os.path.basename(migrated_path)}' (backup).")
    print("[*] La autenticacion ahora se realiza exclusivamente desde SQLite.")


if __name__ == '__main__':
    migrate()
