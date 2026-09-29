import argparse
import hashlib
import hmac
import json
import statistics
import time
import uuid
import requests

BASE_URL = "http://127.0.0.1:8080"


def register(username, password):
    print(f"[*] Registrando usuario: {username}")
    resp = requests.post(
        f"{BASE_URL}/register", json={"username": username, "password": password}
    )
    print("Respuesta:", resp.json())


def login(username, password):
    print(f"\n[*] Iniciando sesión como: {username}")
    resp = requests.post(
        f"{BASE_URL}/login", json={"username": username, "password": password}
    )
    if resp.status_code == 200:
        token = resp.json()["session_token"]
        print(f"[+] Éxito. Token de sesión: {token[:10]}...")
        return token
    else:
        print("[-] Fallo de login:", resp.json())
        return None


def send_transfer(session_token):
    payload = {
        "tx_id": str(uuid.uuid4()),
        "origin_account": "ES1234567890123456789012",
        "destination_account": "ES9876543210987654321098",
        "amount": 1500.50,
        "currency": "EUR",
    }

    body_bytes = json.dumps(payload).encode("utf-8")
    nonce = str(uuid.uuid4())
    timestamp = time.time()

    secret_key = session_token.encode("utf-8")
    signature = hmac.new(secret_key, body_bytes, hashlib.sha256).hexdigest()

    headers = {
        "Content-Type": "application/json",
        "X-Signature": signature,
        "X-Nonce": nonce,
        "X-Timestamp": str(timestamp),
        "X-Session-Token": session_token,
    }

    print("\n[>] --- 1. Enviando Transferencia Legítima ---")
    resp = requests.post(
        f"{BASE_URL}/api/v1/transfer", data=body_bytes, headers=headers
    )
    print(f"Status: {resp.status_code}")
    print(f"Body: {resp.json()}")

    return payload, headers, body_bytes


def simulate_mitm(original_payload, original_headers):
    print("\n[>] --- 2. Simulando Ataque Man-in-the-Middle (Alteración de datos) ---")
    print("El atacante cambia 'amount' a 9999.99 con un nuevo Nonce...")

    malicious_payload = original_payload.copy()
    malicious_payload["amount"] = 9999.99
    body_bytes = json.dumps(malicious_payload).encode("utf-8")

    mitm_headers = original_headers.copy()
    mitm_headers["X-Nonce"] = str(uuid.uuid4())

    resp = requests.post(
        f"{BASE_URL}/api/v1/transfer", data=body_bytes, headers=mitm_headers
    )
    print(f"Status MitM (Esperado 401): {resp.status_code}")
    print(f"Respuesta Servidor: {resp.json()}")


def simulate_replay(original_body_bytes, original_headers):
    print("\n[>] --- 3. Simulando Ataque Replay (Reintervención) ---")
    print("El atacante reenvía la misma petición intacta...")

    resp = requests.post(
        f"{BASE_URL}/api/v1/transfer",
        data=original_body_bytes,
        headers=original_headers,
    )
    print(f"Status Replay (Esperado 400): {resp.status_code}")
    print(f"Respuesta Servidor: {resp.json()}")


def simulate_expired_timestamp(session_token, original_payload):
    print("\n[>] --- 4. Simulando Timestamp Expirado ---")
    print("Enviando petición con timestamp de hace 10 minutos...")

    body_bytes = json.dumps(original_payload).encode("utf-8")
    expired_timestamp = time.time() - 600
    nonce = str(uuid.uuid4())

    secret_key = session_token.encode("utf-8")
    signature = hmac.new(secret_key, body_bytes, hashlib.sha256).hexdigest()

    headers = {
        "Content-Type": "application/json",
        "X-Signature": signature,
        "X-Nonce": nonce,
        "X-Timestamp": str(expired_timestamp),
        "X-Session-Token": session_token,
    }

    resp = requests.post(
        f"{BASE_URL}/api/v1/transfer", data=body_bytes, headers=headers
    )
    print(f"Status Timestamp Expirado (Esperado 400): {resp.status_code}")
    print(f"Respuesta Servidor: {resp.json()}")


# ==========================================
# PRUEBAS DE CANAL LATERAL (TIMING ATTACKS)
# ==========================================
def test_timing_login():
    """
    Mide si existe variación de tiempo al validar contraseñas incorrectas
    en la ruta /login (Defensa por hmac.compare_digest).
    """
    print("\n[>] --- 5. Evaluando Canal Lateral por Tiempo: /login ---")
    url = f"{BASE_URL}/login"
    samples = 30

    def measure(password):
        times = []
        for _ in range(samples):
            start = time.perf_counter()
            requests.post(url, json={"username": "testuser", "password": password})
            end = time.perf_counter()
            times.append((end - start) * 1000)
        return statistics.mean(times)

    t1 = measure("Aaaaaaaaaa!")  # Falla desde el inicio
    t2 = measure("Password123?")  # Falla al final del string

    print(f"Tiempo promedio fallo inicio: {t1:.4f} ms")
    print(f"Tiempo promedio fallo final : {t2:.4f} ms")
    print(f"Diferencia: {abs(t1 - t2):.4f} ms (Comprobación de Tiempo Constante)")


def test_timing_hmac(session_token, original_payload, original_headers):
    """
    Mide si existe variación de tiempo al validar firmas HMAC erróneas
    en la ruta /transfer (Defensa por hmac.compare_digest).
    """
    print("\n[>] --- 6. Evaluando Canal Lateral por Tiempo: /api/v1/transfer ---")
    url = f"{BASE_URL}/api/v1/transfer"
    body_bytes = json.dumps(original_payload).encode("utf-8")
    samples = 30

    correct_sig = original_headers["X-Signature"]
    # Firma que falla en el primer carácter
    bad_sig_start = "0" * len(correct_sig)
    # Firma que difiere solo en el último carácter
    bad_sig_end = correct_sig[:-1] + ("0" if correct_sig[-1] != "0" else "1")

    def measure(signature):
        times = []
        for _ in range(samples):
            headers = original_headers.copy()
            headers["X-Signature"] = signature
            headers["X-Nonce"] = str(uuid.uuid4())  # Evitamos la colisión de replay

            start = time.perf_counter()
            requests.post(url, data=body_bytes, headers=headers)
            end = time.perf_counter()
            times.append((end - start) * 1000)
        return statistics.mean(times)

    t_start = measure(bad_sig_start)
    t_end = measure(bad_sig_end)

    print(f"Tiempo promedio firma errónea (inicio): {t_start:.4f} ms")
    print(f"Tiempo promedio firma errónea (final) : {t_end:.4f} ms")
    print(f"Diferencia: {abs(t_start - t_end):.4f} ms (Comprobación de Tiempo Constante)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--action", choices=["demo", "register", "bruteforce", "timing"], default="demo"
    )
    args = parser.parse_args()

    if args.action == "demo":
        token = login("testuser", "Password123!")
        if not token:
            print("Asegúrate de que el servidor está corriendo.")
            exit(1)

        payload, headers, body_bytes = send_transfer(token)
        simulate_mitm(payload, headers)
        simulate_replay(body_bytes, headers)
        simulate_expired_timestamp(token, payload)
        test_timing_login()
        test_timing_hmac(token, payload, headers)

    elif args.action == "timing":
        token = login("testuser", "Password123!")
        if token:
            payload, headers, _ = send_transfer(token)
            test_timing_login()
            test_timing_hmac(token, payload, headers)

    elif args.action == "register":
        register("newuser", "SecurePass123!")

    elif args.action == "bruteforce":
        print("\n[>] --- Simulando Fuerza Bruta (Bloqueo de cuenta) ---")
        for i in range(4):
            print(f"Intento {i+1}:")
            login("testuser", "ContraseñaIncorrecta!")