import os
import sys
import math
import uuid
import sqlite3
import hmac
import hashlib
import secrets
import bcrypt
import time
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

# ==========================================
# CONFIGURACIÓN
# ==========================================
# Nº de fallos de login consecutivos antes del bloqueo (configurable para las pruebas de timing)
MAX_ATTEMPTS = int(os.environ.get("SECBANK_MAX_ATTEMPTS", "3"))
LOCK_SECONDS = 60
SESSION_SECONDS = 3600
REPLAY_WINDOW = 300

# Clave del SERVIDOR para proteger la integridad de los datos en reposo (no está en la BD).
# En producción debe definirse por variable de entorno SECBANK_SERVER_KEY.
SERVER_KEY = os.environ.get("SECBANK_SERVER_KEY", "cambia-esto-en-produccion").encode("utf-8")


# ==========================================
# INTEGRIDAD EN REPOSO (Política: usuarios, sesiones y transferencias)
# ==========================================
def _mac(*fields):
    msg = "|".join(str(f) for f in fields).encode("utf-8")
    return hmac.new(SERVER_KEY, msg, hashlib.sha256).hexdigest()

def user_mac(username, pwd_hash, failed, locked):
    return _mac("user", username, bytes(pwd_hash).hex(), int(failed), float(locked))

def session_mac(username, token, hmac_key, expires):
    return _mac("session", username, token, hmac_key, float(expires))

def tx_mac(tx_id, username, origin, dest, amount, currency, ts):
    return _mac("tx", tx_id, username, origin, dest, float(amount), currency, float(ts))

def _same(a, b):
    return hmac.compare_digest(str(a).encode("utf-8"), str(b or "").encode("utf-8"))


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
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, password_hash BLOB,
                  failed_attempts INTEGER DEFAULT 0, locked_until REAL DEFAULT 0,
                  row_mac TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS sessions
                 (username TEXT, session_token TEXT PRIMARY KEY, hmac_key TEXT, expires_at REAL, row_mac TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS nonces
                 (nonce TEXT PRIMARY KEY, timestamp REAL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS transactions
                 (tx_id TEXT PRIMARY KEY, username TEXT, origin_account TEXT,
                  destination_account TEXT, amount REAL, currency TEXT, timestamp REAL,
                  row_mac TEXT)''')

    # Usuario por defecto para pruebas
    c.execute("SELECT 1 FROM users WHERE username='testuser'")
    if not c.fetchone():
        # RS1: bcrypt con sal aleatoria única embebida en el hash
        pwd_hash = bcrypt.hashpw(b"Password123!", bcrypt.gensalt(rounds=12))
        c.execute("INSERT INTO users (username, password_hash, failed_attempts, locked_until, row_mac) "
                  "VALUES (?, ?, 0, 0.0, ?)",
                  ('testuser', pwd_hash, user_mac('testuser', pwd_hash, 0, 0.0)))
    conn.commit()
    conn.close()

def verify_db():
    """Recorre users, sessions y transactions y devuelve las filas cuyo MAC no coincide."""
    conn = get_db()
    bad = {"users": [], "sessions": [], "transactions": []}
    try:
        for r in conn.execute("SELECT * FROM users").fetchall():
            exp = user_mac(r["username"], r["password_hash"], r["failed_attempts"], r["locked_until"])
            if not _same(exp, r["row_mac"]):
                bad["users"].append(r["username"])
        for r in conn.execute("SELECT * FROM sessions").fetchall():
            exp = session_mac(r["username"], r["session_token"], r["hmac_key"], r["expires_at"])
            if not _same(exp, r["row_mac"]):
                bad["sessions"].append(r["session_token"][:8] + "...")
        for r in conn.execute("SELECT * FROM transactions").fetchall():
            exp = tx_mac(r["tx_id"], r["username"], r["origin_account"], r["destination_account"],
                         r["amount"], r["currency"], r["timestamp"])
            if not _same(exp, r["row_mac"]):
                bad["transactions"].append(r["tx_id"])
    finally:
        conn.close()
    return bad

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
    if not (3 <= len(user.username) <= 32) or len(user.password) < 8:
        raise HTTPException(status_code=422, detail="Usuario (3-32) o contraseña (mín. 8) no válidos.")
    conn = get_db()
    try:
        # RS1: bcrypt genera y embebe la sal automáticamente en el hash
        pwd_hash = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt(rounds=12))
        conn.execute("INSERT INTO users (username, password_hash, failed_attempts, locked_until, row_mac) "
                     "VALUES (?, ?, 0, 0.0, ?)",
                     (user.username, pwd_hash, user_mac(user.username, pwd_hash, 0, 0.0)))
        conn.commit()
        return {"msg": "Usuario registrado exitosamente."}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="El usuario ya existe.")
    finally:
        conn.close()

def _set_user_state(conn, username, pwd_hash, failed, locked):
    conn.execute("UPDATE users SET failed_attempts=?, locked_until=?, row_mac=? WHERE username=?",
                 (failed, locked, user_mac(username, pwd_hash, failed, locked), username))

@app.post("/login")
def login(user: UserAuth):
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM users WHERE username=?", (user.username,)).fetchone()

        if not row:
            # Igualar el coste temporal con un usuario existente (evita enumeración por tiempo)
            bcrypt.checkpw(user.password.encode('utf-8'), DUMMY_HASH)
            raise HTTPException(status_code=401, detail="Credenciales inválidas.")

        # Integridad en reposo de la cuenta (hash, intentos, bloqueo)
        if not _same(user_mac(row["username"], row["password_hash"],
                              row["failed_attempts"], row["locked_until"]), row["row_mac"]):
            raise HTTPException(status_code=403, detail="Integridad de la cuenta comprometida.")

        now = time.time()
        # RS1: Protección contra fuerza bruta (bloqueo temporal)
        if row['locked_until'] > now:
            raise HTTPException(status_code=403, detail="Cuenta bloqueada temporalmente por intentos fallidos.")

        stored_hash = bytes(row['password_hash'])

        # RS1 + RS4: bcrypt.checkpw verifica el hash con comparación en tiempo constante
        if not bcrypt.checkpw(user.password.encode('utf-8'), stored_hash):
            failed = row['failed_attempts'] + 1
            locked = 0.0
            if failed >= MAX_ATTEMPTS:
                locked = now + LOCK_SECONDS
                failed = 0
            _set_user_state(conn, user.username, stored_hash, failed, locked)
            conn.commit()
            raise HTTPException(status_code=401, detail="Credenciales inválidas.")

        # Éxito: reseteo de intentos y limpieza de sesiones caducadas
        _set_user_state(conn, user.username, stored_hash, 0, 0.0)
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))

        # Token de sesión = clave HMAC (32 bytes = 256 bits, CSPRNG)
        session_token = secrets.token_hex(32)
        hmac_key = secrets.token_hex(32)
        expires_at = now + SESSION_SECONDS
        conn.execute("INSERT INTO sessions (username, session_token, hmac_key, expires_at, row_mac) VALUES (?, ?, ?, ?, ?)",
                     (user.username, session_token, hmac_key, expires_at,
                      session_mac(user.username, session_token, hmac_key, expires_at)))
        conn.commit()
        return {"session_token": session_token, "hmac_key": hmac_key, "expires_in": SESSION_SECONDS}
    finally:
        conn.close()


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

    # 1. Formato del nonce y ventana de timestamp
    try:
        uuid.UUID(x_nonce)
    except ValueError:
        raise HTTPException(status_code=400, detail="Nonce inválido (se espera UUID).")
    try:
        ts = float(x_timestamp)
    except ValueError:
        raise HTTPException(status_code=400, detail="Timestamp inválido.")
    if not math.isfinite(ts) or abs(now - ts) > REPLAY_WINDOW:
        raise HTTPException(status_code=400, detail="Timestamp fuera de ventana válida (Posible Replay).")

    body = await request.body()

    conn = get_db()
    try:
        # 2. Purga de nonces caducados (ya no podrían ser válidos por timestamp)
        conn.execute("DELETE FROM nonces WHERE timestamp < ?", (now - 2 * REPLAY_WINDOW,))

        # 3. Autenticar sesión + integridad de la fila de sesión
        session = conn.execute("SELECT * FROM sessions WHERE session_token=?", (x_session_token,)).fetchone()
        if not session or session['expires_at'] < now:
            raise HTTPException(status_code=401, detail="Sesión inválida o expirada.")
        if not _same(session_mac(session["username"], session["session_token"], session["hmac_key"], session["expires_at"]),
                     session["row_mac"]):
            raise HTTPException(status_code=403, detail="Integridad de la sesión comprometida.")

        # 4. RS2: MAC sobre nonce|timestamp|cuerpo
        message = f"{x_nonce}|{x_timestamp}|".encode('utf-8') + body
        expected_mac = hmac.new(session["hmac_key"].encode('utf-8'), message, hashlib.sha256).hexdigest()

        # RS4: comparación en tiempo constante
        if not hmac.compare_digest(expected_mac.encode('utf-8'), x_signature.encode('utf-8')):
            raise HTTPException(status_code=401, detail="Firma HMAC inválida (Fallo de integridad).")

        # 5. Validación del cuerpo (ya autenticado)
        try:
            tx = TransferRequest.model_validate_json(body)
        except Exception:
            raise HTTPException(status_code=422, detail="Cuerpo de transacción inválido.")
        if not math.isfinite(tx.amount) or tx.amount <= 0:
            raise HTTPException(status_code=422, detail="Importe inválido.")

        # 6. RS3: el nonce se registra SOLO si la firma es válida
        try:
            conn.execute("INSERT INTO nonces (nonce, timestamp) VALUES (?, ?)", (x_nonce, now))
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=400, detail="Nonce ya utilizado (Ataque Replay Detectado).")

        # 7. Guardar la transacción con su MAC de integridad en reposo
        try:
            conn.execute("""INSERT INTO transactions
                            (tx_id, username, origin_account, destination_account, amount, currency, timestamp, row_mac)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                         (tx.tx_id, session["username"], tx.origin_account, tx.destination_account,
                          tx.amount, tx.currency, ts,
                          tx_mac(tx.tx_id, session["username"], tx.origin_account, tx.destination_account,
                                 tx.amount, tx.currency, ts)))
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


if __name__ == '__main__':
    bad = verify_db()
    total = sum(len(v) for v in bad.values())
    if total:
        print(f"[!] ALERTA DE INTEGRIDAD: {total} filas manipuladas -> {bad}")
    else:
        print("[+] Verificación de integridad de la base de datos: OK")
    if "--verify" in sys.argv:
        sys.exit(1 if total else 0)
    uvicorn.run(app, host="0.0.0.0", port=8080)