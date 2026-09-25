import sqlite3
import os
import hashlib

def base_de_datos():
    conexion = sqlite3.connect("datos.db")
    cursor = conexion.cursor()

    # TABLA DE USUARIOS
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            salt TEXT NOT NULL
        )
        '''
    )

    # TABLA DE NONCES
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS nonces (
            nonce TEXT PRIMARY KEY,
            timestamp INTEGER NOT NULL
        )
        '''
    )

    # TABLA DE TRANSACCIONES
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS transactions (
            id TEXT PRIMARY KEY,
            origin TEXT NOT NULL,
            destination TEXT NOT NULL, 
            amount REAL NOT NULL,
            currency TEXT NOT NULL,
            timestamp INTEGER NOT NULL
        )
        '''
    )

    conexion.commit()
    conexion.close()

def registrar_usuario(username, password):
    # SALT ALEATORIO
    salt = os.urandom(16)

    # PBKDF2-HMAC-SHA256
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )

    # CONVERTIR A HEXADECIMAL
    salt_hex = salt.hex()
    hash_hex = password_hash.hex()

    # AÑADIR A SQLITE
    conexion = sqlite3.connect("datos.db")
    cursor = conexion.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password, salt) VALUES (?, ?, ?)",
            (username, hash_hex, salt_hex)
        )
        conexion.commit()
        print(f"Usuario {username} registrado con éxito.")
    except sqlite3.IntegrityError:
        print("Error: El usuario ya existe.")
    finally:
        conexion.close()

if __name__ == "__main__":
    base_de_datos()
    registrar_usuario("byak", "22112005")