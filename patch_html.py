import re

with open('index.html', 'r', encoding='utf-8') as f:
    html = f.read()

html = html.replace(
    'token: null,',
    'token: null,\n    hmacKey: null,'
)
html = html.replace(
    'state.token    = data.session_token;\n        state.username = username;',
    'state.token    = data.session_token;\n        state.hmacKey  = data.hmac_key;\n        state.username = username;'
)
html = html.replace(
    'const key = await crypto.subtle.importKey(\n      \'raw\', new TextEncoder().encode(state.token),\n      { name: \'HMAC\', hash: \'SHA-256\' }, false, [\'sign\']\n    );',
    'const key = await crypto.subtle.importKey(\n      \'raw\', new TextEncoder().encode(state.hmacKey),\n      { name: \'HMAC\', hash: \'SHA-256\' }, false, [\'sign\']\n    );'
)
with open('index.html', 'w', encoding='utf-8') as f:
    f.write(html)
