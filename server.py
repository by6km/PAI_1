import sqlite3
import hashlib
import hmac
import secrets
import time
import json
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="SecBank API")

# ==========================================
# BASE DE DATOS
# ==========================================
def get_db():
    conn = sqlite3.connect('secbank.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    # Tabla de Usuarios
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, salt BLOB, password_hash BLOB, 
                  failed_attempts INTEGER DEFAULT 0, locked_until REAL DEFAULT 0)''')
    # Tabla de Sesiones
    c.execute('''CREATE TABLE IF NOT EXISTS sessions
                 (username TEXT, session_token TEXT PRIMARY KEY, expires_at REAL)''')
    # Tabla de Nonces (Protección Replay)
    c.execute('''CREATE TABLE IF NOT EXISTS nonces
                 (nonce TEXT PRIMARY KEY, timestamp REAL)''')
    
    # Usuario por defecto para pruebas
    c.execute("SELECT * FROM users WHERE username='testuser'")
    if not c.fetchone():
        salt = secrets.token_bytes(32)
        pwd = "Password123!"
        # RS1: Derivación robusta con PBKDF2-HMAC-SHA256
        pwd_hash = hashlib.pbkdf2_hmac('sha256', pwd.encode('utf-8'), salt, 100000)
        c.execute("INSERT INTO users (username, salt, password_hash) VALUES (?, ?, ?)", 
                  ('testuser', salt, pwd_hash))
    conn.commit()
    conn.close()

init_db()

# ==========================================
# RUTAS DE USUARIO (RS1)
# ==========================================
class UserAuth(BaseModel):
    username: str
    password: str

@app.post("/register")
def register(user: UserAuth):
    conn = get_db()
    c = conn.cursor()
    try:
        salt = secrets.token_bytes(32) # Salt aleatorio de 256 bits
        pwd_hash = hashlib.pbkdf2_hmac('sha256', user.password.encode('utf-8'), salt, 100000)
        c.execute("INSERT INTO users (username, salt, password_hash) VALUES (?, ?, ?)", 
                  (user.username, salt, pwd_hash))
        conn.commit()
        return {"msg": "Usuario registrado exitosamente."}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="El usuario ya existe.")
    finally:
        conn.close()

@app.post("/login")
def login(user: UserAuth):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT salt, password_hash, failed_attempts, locked_until FROM users WHERE username=?", (user.username,))
    row = c.fetchone()
    
    if not row:
        raise HTTPException(status_code=401, detail="Credenciales inválidas.")
    
    current_time = time.time()
    # RS1: Protección contra fuerza bruta (Bloqueo)
    if row['locked_until'] > current_time:
        raise HTTPException(status_code=403, detail="Cuenta bloqueada temporalmente por intentos fallidos.")

    salt = row['salt']
    stored_hash = row['password_hash']
    pwd_hash = hashlib.pbkdf2_hmac('sha256', user.password.encode('utf-8'), salt, 100000)
    
    # RS4: Comparación en tiempo constante de hashes de contraseñas
    if not hmac.compare_digest(stored_hash, pwd_hash):
        failed_attempts = row['failed_attempts'] + 1
        locked_until = 0
        if failed_attempts >= 3:
            locked_until = current_time + 60 # Bloqueo de 60 segundos
            failed_attempts = 0 
        c.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE username=?", 
                  (failed_attempts, locked_until, user.username))
        conn.commit()
        raise HTTPException(status_code=401, detail="Credenciales inválidas.")

    # Reseteo de intentos tras éxito
    c.execute("UPDATE users SET failed_attempts=0, locked_until=0 WHERE username=?", (user.username,))
    
    # Creación de token de sesión (32 bytes = 256 bits)
    session_token = secrets.token_hex(32)
    expires_at = current_time + 3600 # 1 hora
    c.execute("INSERT INTO sessions (username, session_token, expires_at) VALUES (?, ?, ?)", 
              (user.username, session_token, expires_at))
    conn.commit()
    conn.close()
    
    return {"session_token": session_token, "expires_in": 3600}

# ==========================================
# RUTA DE TRANSFERENCIA (RS2, RS3, RS4)
# ==========================================
class TransferRequest(BaseModel):
    tx_id: str
    origin_account: str
    destination_account: str
    amount: float
    currency: str

@app.post("/api/v1/transfer")
async def transfer(
    request: Request,
    x_signature: str = Header(..., description="Firma HMAC-SHA256"),
    x_nonce: str = Header(..., description="UUIDv4 único"),
    x_timestamp: float = Header(..., description="Timestamp Unix"),
    x_session_token: str = Header(...)
):
    current_time = time.time()
    
    # 1. Validación de Timestamp (Replay Window: ej. 5 minutos)
    if abs(current_time - x_timestamp) > 300:
        raise HTTPException(status_code=400, detail="Timestamp fuera de ventana válida (Posible Replay).")

    conn = get_db()
    c = conn.cursor()
    
    # 2. RS3: Protección Replay (Comprobar Nonce)
    c.execute("SELECT nonce FROM nonces WHERE nonce=?", (x_nonce,))
    if c.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Nonce ya utilizado (Ataque Replay Detectado).")
        
    c.execute("INSERT INTO nonces (nonce, timestamp) VALUES (?, ?)", (x_nonce, current_time))
    
    # 3. Autenticar Sesión y Obtener Clave
    c.execute("SELECT username, expires_at FROM sessions WHERE session_token=?", (x_session_token,))
    session = c.fetchone()
    if not session or session['expires_at'] < current_time:
        conn.close()
        raise HTTPException(status_code=401, detail="Sesión inválida o expirada.")
        
    # 4. RS2: Integridad y Autenticidad (Calcular MAC esperado)
    body = await request.body()
    # Usamos el session_token como clave secreta compartida (>= 256 bits)
    secret_key = x_session_token.encode('utf-8')
    expected_mac = hmac.new(secret_key, body, hashlib.sha256).hexdigest()
    
    # RS4: Mitigación de Canales Laterales de Tiempo (Comparación en tiempo constante)
    if not hmac.compare_digest(expected_mac, x_signature):
        conn.close()
        raise HTTPException(status_code=401, detail="Firma HMAC inválida (Fallo de integridad).")

    conn.commit()
    conn.close()
    
    return {"status": "SUCCESS", "msg": "Transferencia verificada y procesada correctamente."}

if __name__ == '__main__':
    uvicorn.run(app, host="0.0.0.0", port=8080)
