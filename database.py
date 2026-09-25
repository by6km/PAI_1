import sqlite3

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

if __name__ == "__main__":
    base_de_datos()