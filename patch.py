import re

with open('server.py', 'r', encoding='utf-8') as f:
    server_code = f.read()

server_code = server_code.replace(
    'def session_mac(username, token, expires):',
    'def session_mac(username, token, hmac_key, expires):'
)
server_code = server_code.replace(
    'return _mac("session", username, token, float(expires))',
    'return _mac("session", username, token, hmac_key, float(expires))'
)
server_code = server_code.replace(
    '(username TEXT, session_token TEXT PRIMARY KEY, expires_at REAL, row_mac TEXT)',
    '(username TEXT, session_token TEXT PRIMARY KEY, hmac_key TEXT, expires_at REAL, row_mac TEXT)'
)
server_code = server_code.replace(
    'exp = session_mac(r["username"], r["session_token"], r["expires_at"])',
    'exp = session_mac(r["username"], r["session_token"], r["hmac_key"], r["expires_at"])'
)
server_code = server_code.replace(
    'session_token = secrets.token_hex(32)',
    'session_token = secrets.token_hex(32)\n        hmac_key = secrets.token_hex(32)'
)
server_code = server_code.replace(
    'conn.execute("INSERT INTO sessions (username, session_token, expires_at, row_mac) VALUES (?, ?, ?, ?)",\n                     (user.username, session_token, expires_at,\n                      session_mac(user.username, session_token, expires_at)))',
    'conn.execute("INSERT INTO sessions (username, session_token, hmac_key, expires_at, row_mac) VALUES (?, ?, ?, ?, ?)",\n                     (user.username, session_token, hmac_key, expires_at,\n                      session_mac(user.username, session_token, hmac_key, expires_at)))'
)
server_code = server_code.replace(
    'return {"session_token": session_token, "expires_in": SESSION_SECONDS}',
    'return {"session_token": session_token, "hmac_key": hmac_key, "expires_in": SESSION_SECONDS}'
)
server_code = server_code.replace(
    'if not _same(session_mac(session["username"], session["session_token"], session["expires_at"]),\n                     session["row_mac"]):',
    'if not _same(session_mac(session["username"], session["session_token"], session["hmac_key"], session["expires_at"]),\n                     session["row_mac"]):'
)
server_code = server_code.replace(
    'expected_mac = hmac.new(x_session_token.encode(\'utf-8\'), message, hashlib.sha256).hexdigest()',
    'expected_mac = hmac.new(session["hmac_key"].encode(\'utf-8\'), message, hashlib.sha256).hexdigest()'
)

with open('server.py', 'w', encoding='utf-8') as f:
    f.write(server_code)

with open('client.py', 'r', encoding='utf-8') as f:
    client_code = f.read()

client_code = client_code.replace(
    'token = resp.json()["session_token"]\n        print(f"[+] Éxito. Token de sesión: {token[:10]}...")\n        return token',
    'token = resp.json()["session_token"]\n        hmac_key = resp.json()["hmac_key"]\n        print(f"[+] Éxito. Token de sesión: {token[:10]}...")\n        return token, hmac_key'
)
client_code = client_code.replace(
    'return None',
    'return None, None'
)
client_code = client_code.replace(
    'def send_transfer(session_token):',
    'def send_transfer(session_token, hmac_key):'
)
client_code = client_code.replace(
    'signature = sign(session_token, nonce, ts_str, body_bytes)',
    'signature = sign(hmac_key, nonce, ts_str, body_bytes)'
)
client_code = client_code.replace(
    'def simulate_expired_timestamp(session_token, original_payload):',
    'def simulate_expired_timestamp(session_token, hmac_key, original_payload):'
)
client_code = client_code.replace(
    'def test_timing_login():',
    'def test_timing_login():\n    import os\n    if os.environ.get("SECBANK_MAX_ATTEMPTS") != "100000":\n        print("\\n[!] Saltando test_timing_login() porque SECBANK_MAX_ATTEMPTS no es 100000.")\n        return'
)
client_code = client_code.replace(
    'requests.post(url, json={"username": "testuser", "password": "Password123?"})',
    'res = requests.post(url, json={"username": "testuser", "password": "Password123?"})\n        if res.status_code == 403:\n            print("\\n[!] ATENCIÓN: El servidor devolvió 403. La cuenta está bloqueada y la prueba de timing está invalidada.")\n            break'
)

client_code = client_code.replace(
    'token = login("testuser", "Password123!")\n        if not token:\n            print("Asegúrate de que el servidor está corriendo.")\n            exit(1)',
    'token, hmac_key = login("testuser", "Password123!")\n        if not token:\n            print("Asegúrate de que el servidor está corriendo.")\n            exit(1)'
)
client_code = client_code.replace(
    'payload, headers, body_bytes = send_transfer(token)',
    'payload, headers, body_bytes = send_transfer(token, hmac_key)'
)
client_code = client_code.replace(
    'simulate_expired_timestamp(token, payload)',
    'simulate_expired_timestamp(token, hmac_key, payload)'
)
client_code = client_code.replace(
    'test_timing_login()\n        test_timing_hmac(token, payload, headers)',
    '# test_timing_login() eliminado del bloque demo\n        test_timing_hmac(token, payload, headers)'
)

client_code = client_code.replace(
    'elif args.action == "timing":\n        token = login("testuser", "Password123!")\n        if token:\n            payload, headers, _ = send_transfer(token)\n            test_timing_login()\n            test_timing_hmac(token, payload, headers)',
    'elif args.action == "timing":\n        token, hmac_key = login("testuser", "Password123!")\n        if token:\n            payload, headers, _ = send_transfer(token, hmac_key)\n            test_timing_login()\n            test_timing_hmac(token, payload, headers)'
)

with open('client.py', 'w', encoding='utf-8') as f:
    f.write(client_code)

