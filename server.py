import sqlite3
import hmac
import os
import hashlib
import secrets
import bcrypt
import time
import json
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="SecBank API")

# CORS: permite peticiones desde el frontend HTML local
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

MAX_ATTEMPTS = int(os.environ.get("SECBANK_MAX_ATTEMPTS", "3"))

SERVER_KEY = os.environ.get("SECBANK_SERVER_KEY", "cambia-esto-en-produccion").encode()

def row_mac(*fields):
    msg = "|".join(str(f) for f in fields).encode()
    return hmac.new(SERVER_KEY, msg, hashlib.sha256).hexdigest()

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
    # Tabla de Transaccciones
    c.execute('''CREATE TABLE IF NOT EXISTS transactions
                 (tx_id TEXT PRIMARY KEY, origin_account TEXT, destination_account TEXT, 
                  amount REAL, currency TEXT, timestamp REAL, row_mac TEXT)''')
    
    # Usuario por defecto para pruebas
    c.execute("SELECT * FROM users WHERE username='testuser'")
    if not c.fetchone():
        pwd = "Password123!"
        # RS1: Hash seguro de contraseña con bcrypt (salt embebido automáticamente)
        pwd_hash = bcrypt.hashpw(pwd.encode('utf-8'), bcrypt.gensalt(rounds=12))
        c.execute("INSERT INTO users (username, salt, password_hash) VALUES (?, ?, ?)",
                  ('testuser', None, pwd_hash))
    conn.commit()
    conn.close()

init_db()

# Hash falso para igualar el tiempo de /login cuando el usuario no existe
DUMMY_HASH = bcrypt.hashpw(b"dummy", bcrypt.gensalt(rounds=12))

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
        # RS1: bcrypt genera y embebe el salt automáticamente en el hash
        pwd_hash = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt(rounds=12))
        c.execute("INSERT INTO users (username, salt, password_hash) VALUES (?, ?, ?)",
                  (user.username, None, pwd_hash))
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
        conn.close()
        bcrypt.checkpw(user.password.encode('utf-8'), DUMMY_HASH)
        raise HTTPException(status_code=401, detail="Credenciales inválidas.")
    
    current_time = time.time()
    # RS1: Protección contra fuerza bruta (Bloqueo)
    if row['locked_until'] > current_time:
        raise HTTPException(status_code=403, detail="Cuenta bloqueada temporalmente por intentos fallidos.")

    stored_hash = bytes(row['password_hash'])

    # RS1 + RS4: bcrypt.checkpw verifica el hash e incorpora comparación en tiempo constante
    if not bcrypt.checkpw(user.password.encode('utf-8'), stored_hash):
        failed_attempts = row['failed_attempts'] + 1
        locked_until = 0
        if failed_attempts >= MAX_ATTEMPTS:
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
    x_timestamp: str = Header(..., description="Timestamp Unix (se firma tal cual llega)"),
    x_session_token: str = Header(...)
):
    now = time.time()

    # 1. Ventana de timestamp
    try:
        ts = float(x_timestamp)
    except ValueError:
        raise HTTPException(status_code=400, detail="Timestamp inválido.")
    if abs(now - ts) > 300:
        raise HTTPException(status_code=400, detail="Timestamp fuera de ventana válida (Posible Replay).")

    conn = get_db()
    c = conn.cursor()
    try:
        # 2. Purga de nonces caducados (ya no pueden ser válidos por timestamp)
        c.execute("DELETE FROM nonces WHERE timestamp < ?", (now - 600,))

        # 3. Autenticar sesión
        c.execute("SELECT username, expires_at FROM sessions WHERE session_token=?", (x_session_token,))
        session = c.fetchone()
        if not session or session['expires_at'] < now:
            raise HTTPException(status_code=401, detail="Sesión inválida o expirada.")

        # 4. RS2: MAC sobre nonce|timestamp|cuerpo
        body = await request.body()
        message = f"{x_nonce}|{x_timestamp}|".encode('utf-8') + body
        expected_mac = hmac.new(x_session_token.encode('utf-8'), message, hashlib.sha256).hexdigest()

        # RS4: comparación en tiempo constante
        if not hmac.compare_digest(expected_mac.encode('utf-8'), x_signature.encode('utf-8')):
            raise HTTPException(status_code=401, detail="Firma HMAC inválida (Fallo de integridad).")

        # 5. RS3: el nonce se registra SOLO si la firma es válida
        try:
            c.execute("INSERT INTO nonces (nonce, timestamp) VALUES (?, ?)", (x_nonce, now))
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=400, detail="Nonce ya utilizado (Ataque Replay Detectado).")

        # 6. Guardar la transacción legítima
        data = json.loads(body)
        try:
            mac = row_mac(data['tx_id'], data['origin_account'], data['destination_account'],
                          float(data['amount']), data['currency'], float(ts))
            c.execute("""INSERT INTO transactions
                         (tx_id, origin_account, destination_account, amount, currency, timestamp, row_mac)
                         VALUES (?, ?, ?, ?, ?, ?, ?)""",
                      (data['tx_id'], data['origin_account'], data['destination_account'],
                       data['amount'], data['currency'], ts, mac))
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="tx_id duplicado.")
        conn.commit()
    finally:
        conn.close()

    return {"status": "SUCCESS", "msg": "Transferencia verificada y procesada correctamente."}

# ==========================================
# LOGOUT (RF1.d)
# ==========================================
@app.post("/logout")
def logout(x_session_token: str = Header(...)):
    conn = get_db()
    try:
        conn.execute("DELETE FROM sessions WHERE session_token=?", (x_session_token,))
        conn.commit()
    finally:
        conn.close()
    return {"msg": "Sesión cerrada."}

def verify_db():
    """Devuelve los tx_id cuyo row_mac no coincide (fila manipulada)."""
    conn = get_db()
    try:
        rows = conn.execute("SELECT * FROM transactions").fetchall()
    finally:
        conn.close()
    bad = []
    for r in rows:
        esperado = row_mac(r["tx_id"], r["origin_account"], r["destination_account"],
                           float(r["amount"]), r["currency"], float(r["timestamp"]))
        if not hmac.compare_digest(esperado.encode(), (r["row_mac"] or "").encode()):
            bad.append(r["tx_id"])
    return bad

_bad = verify_db()
if _bad:
    print(f"[!] ALERTA: {len(_bad)} transacciones con integridad rota: {_bad}")

if __name__ == '__main__':
    uvicorn.run(app, host="0.0.0.0", port=8080)