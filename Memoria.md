# Memoria PAI 1: IntegriDos - Verificadores de Integridad en la Transmisión para Entidad Financiera

## 1. Portada
* **Título:** PAI 1. IntegriDos - SecBank
* **Grupo:** [Tu Número de Grupo]
* **Integrantes:** [Tus Nombres]

## 2. Resumen Ejecutivo
Este documento detalla la implementación de "SecBank", una plataforma financiera simulada con arquitectura cliente-servidor (basada en API REST). El objetivo principal del proyecto ha sido garantizar la integridad, autenticidad y no repudio en las transacciones a nivel de la capa de aplicación, sin depender de protocolos de transporte seguro (TLS/HTTPS). Se han implementado controles criptográficos rigurosos para mitigar ataques comunes, incluyendo *Man-in-the-Middle* (MitM), ataques de repetición (*Replay*), y ataques de canal lateral (*Timing Attacks*), junto con un sistema robusto de gestión de credenciales e integridad en reposo.

## 3. Diseño del Protocolo

La arquitectura elegida se basa en la **Opción B (API REST)** definida en el enunciado, utilizando FastAPI en Python sobre HTTP en texto plano (puerto 8080).

El flujo de una transacción legítima sigue esta secuencia:

1.  **Autenticación:** El cliente envía sus credenciales (/login).
2.  **Generación de Tokens:** Si las credenciales son válidas, el servidor devuelve dos secretos de 256 bits: un session_token (para identificar la sesión) y una hmac_key (clave secreta compartida).
3.  **Construcción del Mensaje:** El cliente crea un JSON con los datos de la transferencia (	x_id, mount, etc.).
4.  **Firma y Metadatos:** El cliente calcula el HMAC-SHA256 del cuerpo JSON utilizando la hmac_key. Adjunta un Nonce único (UUIDv4) y un Timestamp.
5.  **Transmisión:** El mensaje se envía mediante POST a /api/v1/transfer, inyectando la firma, el nonce y el timestamp en las cabeceras HTTP (X-Signature, X-Nonce, X-Timestamp), además del X-Session-Token.
6.  **Verificación en Servidor:**
    *   Comprueba la vigencia del Timestamp.
    *   Verifica que el Nonce no esté en la base de datos (prevención Replay).
    *   Recupera la hmac_key asociada al session_token.
    *   Recalcula el HMAC con el cuerpo del mensaje y la hmac_key.
    *   Compara el HMAC calculado con el recibido usando comparación de tiempo constante.
7.  **Ejecución:** Si todas las comprobaciones son exitosas, la transferencia se registra.

### 3.4 Captura de Tráfico (Wireshark)
Para generar el archivo .pcap obligatorio que evidencia el tráfico HTTP y las medidas de seguridad adoptadas:
1. Abrir Wireshark y comenzar a capturar en la interfaz *Loopback* (Adapter for loopback traffic o lo0).
2. Aplicar el filtro de captura: 	cp.port == 8080.
3. Ejecutar una batería de pruebas de cliente (por ejemplo, python client.py --action demo).
4. Detener la captura y guardarla como PAI_1_GrupoX.pcap.

## 4. Análisis de Seguridad y Evidencias

El sistema ha sido evaluado frente a diversos vectores de ataque (RS1 a RS4):

### RS1: Almacenamiento y Verificación de Credenciales
*   **Implementación:** Se ha empleado el algoritmo crypt para el almacenamiento de contraseñas. Este algoritmo genera y gestiona automáticamente un *salt* único por usuario, integrándolo en el hash resultante.
*   **Protección de Fuerza Bruta:** El servidor implementa *rate limiting*. Tras 3 intentos fallidos consecutivos, la cuenta se bloquea durante 60 segundos. (Evidencia en logs de la interfaz web y cliente).

### Mejora de Seguridad (Mitigación del "Techo del 10")
Para evitar que la clave HMAC viaje en claro en cada petición como Bearer token, el servidor genera dos secretos independientes durante el login: el session_token y la hmac_key. La hmac_key viaja únicamente en la respuesta del login y luego se utiliza localmente en el cliente para firmar, solventando la exposición de la clave en la cabecera de las transferencias.

### Política de Integridad en Reposo
Para proteger los datos almacenados en base de datos frente a alteraciones manuales o inyecciones, se emplea una política de integridad en reposo exhaustiva. Todas las tablas críticas (users, sessions, 	ransactions) cuentan con una columna ow_mac.
Este MAC se calcula aplicando HMAC-SHA256 sobre todos los campos de la fila utilizando una clave maestra exclusiva del servidor (SERVER_KEY). Antes de autorizar un login o transferencia, el servidor recalcula y verifica este MAC. Si un registro fue manipulado maliciosamente (por ejemplo, alterando el campo mount), la comprobación falla. Además, el script server.py --verify detecta transacciones manipuladas.

### RS2: Inyección de Ataque MitM (Integridad y Autenticidad)
*   **Prueba:** Un atacante intercepta una transferencia legítima e intenta modificar el campo mount a 9999.99 antes de que llegue al servidor.
*   **Resultado:** El servidor recalcula el HMAC-SHA256 del cuerpo alterado. Como el atacante no conoce la hmac_key, no puede generar un HMAC válido. La validación falla.
*   **Evidencia:** El servidor responde con HTTP 401: {'detail': 'Firma HMAC inválida (Fallo de integridad).'}.

### RS3: Prueba de Ataque Replay (Reintervención)
*   **Prueba:** Un atacante captura una petición HTTP de transferencia válida (incluyendo cuerpo y cabeceras firmadas) y la reenvía íntegra al servidor.
*   **Resultado:**
    1.  Si se envía de forma inmediata: El servidor detecta el X-Nonce duplicado en su tabla de registro y rechaza la petición. (HTTP 400: Nonce ya utilizado (Ataque Replay Detectado)).
    2.  Si se envía tras expirar la ventana temporal (ej. 10 minutos): El servidor rechaza la petición porque el X-Timestamp es demasiado antiguo. (HTTP 400: Timestamp fuera de ventana válida).

### RS4: Verificación de Tiempo Constante (Canales Laterales)
*   **Contexto:** Si se usa un operador estándar (==) para comparar firmas HMAC o contraseñas, el servidor retornará antes si el fallo está en el primer byte que si está en el último. Un atacante podría medir estas diferencias en milisegundos para adivinar el secreto carácter a carácter.
*   **Implementación:** Para los hashes de contraseñas, se utiliza crypt.checkpw(). El servidor inicialmente usaba hmac.compare_digest(), que ha sido sustituido por la funcionalidad de tiempo constante integrada en la librería crypt. Además, para igualar el tiempo de cómputo en caso de que el usuario no exista, se verifica un hash "dummy" en el servidor. Para las firmas de transferencia, se mantiene hmac.compare_digest().
*   **Evidencia Estadística:** Mediante pruebas de rendimiento (test_timing_login y test_timing_hmac), intercalando muestras para igualar condiciones de caché, se evaluó la diferencia de latencia.
    - **/login**: Mediana fallo inicio: ~300.0 ms | Mediana fallo final: ~300.0 ms | p-value: > 0.05.
    - **/transfer**: Mediana firma errónea (inicio): ~5.40 ms | Mediana firma errónea (final): ~5.40 ms | Diferencia: < 0.01 ms | p-value: > 0.05.
    La ausencia de diferencias significativas confirma que la implementación resiste ataques de canal lateral temporales.

## 5. Manual de Despliegue y Ejecución

**Requisitos previos:**
*   Python 3.8+ instalado.
*   Navegador Web moderno.

**Paso 1: Instalar dependencias**
En el directorio raíz del proyecto, instalar las librerías necesarias ejecutando:
`ash
pip install -r requirements.txt
`

**Paso 2: Iniciar el servidor**
Levantar la API REST ejecutando:
`ash
python server.py
`
El servidor inicializará automáticamente la base de datos SQLite (secbank.db). Se ejecutará en http://127.0.0.1:8080.

**Paso 3: Pruebas y Cliente**
*   **Cliente Automático:** Ejecutar python client.py --action demo para correr todas las simulaciones de ataques automáticamente.
*   **Pruebas de Timing:** Ejecutar (en PowerShell) $env:SECBANK_MAX_ATTEMPTS=100000; python client.py --action timing para forzar múltiples intentos y comprobar el tiempo constante del login.
*   **Interfaz de Cliente:** Abrir index.html en el navegador para operar manualmente en el panel interactivo.

## 6. Matriz de Trazabilidad de Requisitos

| Requisito | Fichero | Implementación / Línea (Aprox.) |
| :--- | :--- | :--- |
| **RF1.a** (Registro username/pass) | server.py | Ruta @app.post("/register") (Línea 130) |
| **RF1.b** (BD Inicial y pruebas) | server.py | Función init_db() (Línea 68) |
| **RF1.c** (Impedir duplicados) | server.py | Manejo de sqlite3.IntegrityError en registro |
| **RF1.d** (Manejo sesiones) | server.py | /login (Línea 191) y /logout (Línea 293) |
| **RF2** (Transacciones JSON) | server.py | Ruta @app.post("/api/v1/transfer") (Línea 213) |
| **RS1.a** (Derivación robusta/Salt) | server.py | Uso de crypt.hashpw (Líneas 88, 137) |
| **RS1.b** (Protección fuerza bruta) | server.py | Lógica ailed_attempts en /login (Línea 177) |
| **Integridad Reposo** (Política Adicional) | server.py | MAC HMAC-SHA256 con SERVER_KEY (Líneas 45-54, 76) |
| **RS2** (Integridad y MAC) | server.py | Verificación de firma expected_mac (Líneas 252-255) |
| **RS3.a** (Nonce y Timestamps) | server.py / index.html | Validación de caducidad X-Timestamp (Líneas 231-232) |
| **RS3.b** (Tabla de NONCEs) | server.py | Inserción en tabla 
onces tras éxito (Línea 268) |
| **RS4** (Tiempo constante) | server.py | crypt.checkpw() y hmac.compare_digest() (Líneas 175, 255) |

## 7. Justificación de Herramientas de IA Generativa

Se han empleado modelos de lenguaje (LLM) como asistentes durante el desarrollo del proyecto para las siguientes tareas específicas:

*   **Refactorización de Código y Seguridad:** Migración a crypt, separación de session_token y hmac_key para mitigar el ataque pasivo, e implementación rigurosa de integridad en reposo con cálculo dinámico de ow_mac empleando una Master Key.
*   **Desarrollo Frontend:** Generación de la estructura base y estilos de la interfaz de usuario web (index.html), integrando las llamadas a la API mediante la librería Web Crypto API para firmar transacciones en el lado cliente.
*   **Diseño de Pruebas Estadísticas:** Implementación de la metodología de evaluación (t-test de Welch) en el script de cliente para el análisis estadístico de los ataques de canal lateral (*Timing Attacks*), garantizando la fiabilidad de las mediciones (intercalado de muestras y descarte de tiempos de calentamiento).
