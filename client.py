import requests
import json
import time
import hmac
import hashlib
import uuid
import argparse

BASE_URL = "http://127.0.0.1:8080"

def register(username, password):
    print(f"[*] Registrando usuario: {username}")
    resp = requests.post(f"{BASE_URL}/register", json={"username": username, "password": password})
    print("Respuesta:", resp.json())

def login(username, password):
    print(f"\n[*] Iniciando sesión como: {username}")
    resp = requests.post(f"{BASE_URL}/login", json={"username": username, "password": password})
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
        "currency": "EUR"
    }
    
    body_bytes = json.dumps(payload).encode('utf-8')
    nonce = str(uuid.uuid4())
    timestamp = time.time()
    
    # Firmar el cuerpo usando el token de sesión como clave secreta (RS2)
    secret_key = session_token.encode('utf-8')
    signature = hmac.new(secret_key, body_bytes, hashlib.sha256).hexdigest()
    
    headers = {
        "Content-Type": "application/json",
        "X-Signature": signature,
        "X-Nonce": nonce,
        "X-Timestamp": str(timestamp),
        "X-Session-Token": session_token
    }
    
    print("\n[>] --- Enviando Transferencia Legítima ---")
    resp = requests.post(f"{BASE_URL}/api/v1/transfer", data=body_bytes, headers=headers)
    print(f"Status: {resp.status_code}")
    print(f"Body: {resp.json()}")
    
    return payload, headers, body_bytes

def simulate_mitm(session_token, original_payload, original_headers):
    print("\n[>] --- Simulando Ataque Man-in-the-Middle (MitM) ---")
    print("El atacante intercepta y cambia el 'amount' a 9999.99")
    
    malicious_payload = original_payload.copy()
    malicious_payload["amount"] = 9999.99
    
    body_bytes = json.dumps(malicious_payload).encode('utf-8')
    
    # El atacante envía el payload modificado con la firma original
    resp = requests.post(f"{BASE_URL}/api/v1/transfer", data=body_bytes, headers=original_headers)
    print(f"Status MitM: {resp.status_code}")
    print(f"Respuesta Servidor: {resp.json()}")

def simulate_replay(original_body_bytes, original_headers):
    print("\n[>] --- Simulando Ataque Replay (Reintervención) ---")
    print("El atacante intercepta la petición y la reenvía íntegra.")
    
    resp = requests.post(f"{BASE_URL}/api/v1/transfer", data=original_body_bytes, headers=original_headers)
    print(f"Status Replay: {resp.status_code}")
    print(f"Respuesta Servidor: {resp.json()}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--action', choices=['demo', 'register', 'bruteforce'], default='demo')
    args = parser.parse_args()
    
    if args.action == 'demo':
        token = login("testuser", "Password123!")
        if not token:
            print("Asegúrate de que el servidor está corriendo.")
            exit(1)
            
        payload, headers, body_bytes = send_transfer(token)
        simulate_mitm(token, payload, headers)
        simulate_replay(body_bytes, headers)
        
    elif args.action == 'register':
        register("newuser", "SecurePass123!")
        
    elif args.action == 'bruteforce':
        print("\n[>] --- Simulando Fuerza Bruta (Bloqueo de cuenta) ---")
        for i in range(4):
            print(f"Intento {i+1}:")
            login("testuser", "ContraseñaIncorrecta!")