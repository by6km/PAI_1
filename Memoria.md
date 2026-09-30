# Memoria PAI 1: IntegriDos - Verificadores de Integridad en la Transmisión para Entidad Financiera

## 1. Portada
* **Título:** PAI 1. IntegriDos - SecBank
* **Grupo:** [Tu Número de Grupo]
* **Integrantes:** [Tus Nombres]

## 2. Resumen Ejecutivo
Este documento detalla la implementación de "SecBank", una plataforma financiera simulada con arquitectura cliente-servidor (basada en API REST). El objetivo principal del proyecto ha sido garantizar la integridad, autenticidad y no repudio en las transacciones a nivel de la capa de aplicación, sin depender de protocolos de transporte seguro (TLS/HTTPS). Se han implementado controles criptográficos rigurosos para mitigar ataques comunes, incluyendo *Man-in-the-Middle* (MitM), ataques de repetición (*Replay*), y ataques de canal lateral (*Timing Attacks*), junto con un sistema robusto de gestión de credenciales.

## 3. Diseño del Protocolo

La arquitectura elegida se basa en la **Opción B (API REST)** definida en el enunciado, utilizando FastAPI en Python sobre HTTP en texto plano (puerto 8080).

El flujo de una transacción legítima sigue esta secuencia:

1.  **Autenticación:** El cliente envía sus credenciales (`/login`).
2.  **Generación de Token:** Si las credenciales son válidas, el servidor devuelve un `session_token` de 256 bits, que actuará como clave secreta compartida.
3.  **Construcción del Mensaje:** El cliente crea un JSON con los datos de la transferencia (`tx_id`, `amount`, etc.).
4.  **Firma y Metadatos:** El cliente calcula el HMAC-SHA256 del cuerpo JSON utilizando el `session_token` como clave. Adjunta un `Nonce` único (UUIDv4) y un `Timestamp`.
5.  **Transmisión:** El mensaje se envía mediante POST a `/api/v1/transfer`, inyectando la firma, el nonce y el timestamp en las cabeceras HTTP (`X-Signature`, `X-Nonce`, `X-Timestamp`).
6.  **Verificación en Servidor:**
    *   Comprueba la vigencia del `Timestamp`.
    *   Verifica que el `Nonce` no esté en la base de datos (prevención Replay).
    *   Recalcula el HMAC con el cuerpo del mensaje y el token de sesión almacenado.
    *   Compara el HMAC calculado con el recibido usando comparación de tiempo constante.
7.  **Ejecución:** Si todas las comprobaciones son exitosas, la transferencia se registra.

## 4. Análisis de Seguridad y Evidencias

El sistema ha sido evaluado frente a diversos vectores de ataque (RS1 a RS4):

### RS1: Almacenamiento y Verificación de Credenciales
*   **Implementación:** Se ha empleado el algoritmo `bcrypt` para el almacenamiento de contraseñas. Este algoritmo genera y gestiona automáticamente un *salt* único por usuario, integrándolo en el hash resultante.
*   **Protección de Fuerza Bruta:** El servidor implementa *rate limiting*. Tras 3 intentos fallidos consecutivos, la cuenta se bloquea durante 60 segundos. (Evidencia en logs de la interfaz web).

### RS2: Inyección de Ataque MitM (Integridad y Autenticidad)
*   **Prueba:** Un atacante intercepta una transferencia legítima e intenta modificar el campo `amount` a `9999.99` antes de que llegue al servidor.
*   **Resultado:** El servidor recalcula el HMAC-SHA256 del cuerpo alterado. Como el atacante no conoce la clave secreta (token), no puede generar un HMAC válido para el nuevo cuerpo. La validación falla.
*   **Evidencia:** El servidor responde con HTTP 401: `{'detail': 'Firma HMAC inválida (Fallo de integridad).'}`.

### RS3: Prueba de Ataque Replay (Reintervención)
*   **Prueba:** Un atacante captura una petición HTTP de transferencia válida (incluyendo cuerpo y cabeceras firmadas) y la reenvía íntegra al servidor.
*   **Resultado:**
    1.  Si se envía de forma inmediata: El servidor detecta el `X-Nonce` duplicado en su tabla de registro y rechaza la petición. (HTTP 400: `Nonce ya utilizado (Ataque Replay Detectado)`).
    2.  Si se envía tras expirar la ventana temporal (ej. 10 minutos): El servidor rechaza la petición porque el `X-Timestamp` es demasiado antiguo. (HTTP 400: `Timestamp fuera de ventana válida`).

### RS4: Verificación de Tiempo Constante (Canales Laterales)
*   **Contexto:** Si se usa un operador estándar (`==`) para comparar firmas HMAC o contraseñas, el servidor retornará antes si el fallo está en el primer byte que si está en el último. Un atacante podría medir estas diferencias en milisegundos para adivinar el secreto carácter a carácter.
*   **Implementación:** Para los hashes de contraseñas, se utiliza `bcrypt.checkpw()`. El servidor inicialmente usaba `hmac.compare_digest()`, que ha sido sustituido por la funcionalidad de tiempo constante integrada en la librería `bcrypt`. Para las firmas de transferencia, se mantiene `hmac.compare_digest()`. Ambas implementaciones están programadas típicamente en C y aseguran que la comparación evalúe siempre la longitud completa de las cadenas, independientemente de dónde se encuentre el primer carácter discordante.
*   **Evidencia Estadística:** Mediante pruebas de rendimiento intensivas (100 muestras intercaladas, descartando latencia inicial) se evaluó la diferencia de tiempos entre firmas que fallan al inicio frente a las que fallan al final. La prueba t de Welch arrojó un *p-value* > 0.05, indicando que las variaciones observadas (menores a 1 ms) son estadísticamente insignificantes y atribuibles al ruido de la red, demostrando la eficacia de la defensa.

## 5. Manual de Despliegue y Ejecución

**Requisitos previos:**
*   Python 3.8+ instalado.
*   Navegador Web moderno.

**Paso 1: Instalar dependencias**
En el directorio raíz del proyecto, instalar las librerías necesarias ejecutando:
```bash
pip install -r requirements.txt
```
*(Nota: El archivo `requirements.txt` incluye `fastapi`, `uvicorn`, `requests`, `scipy` y `bcrypt`)*.

**Paso 2: Iniciar el servidor**
Levantar la API REST ejecutando:
```bash
python server.py
```
El servidor inicializará automáticamente la base de datos SQLite (`secbank.db`) si no existe, creando el usuario de prueba por defecto. Se ejecutará en `http://127.0.0.1:8080`.

**Paso 3: Interfaz de Cliente**
Para interactuar con la aplicación, simplemente abrir el archivo `index.html` en cualquier navegador web. El frontend cuenta con un panel dedicado para simular y verificar los ataques (MitM, Replay, Fuerza Bruta).

## 6. Matriz de Trazabilidad de Requisitos

| Requisito | Fichero | Implementación / Línea (Aprox.) |
| :--- | :--- | :--- |
| **RF1.a** (Registro username/pass) | `server.py` | Ruta `@app.post("/register")` |
| **RF1.b** (BD Inicial y pruebas) | `server.py` | Función `init_db()` (Usuario 'testuser') |
| **RF1.c** (Impedir duplicados) | `server.py` | Manejo de `sqlite3.IntegrityError` en registro |
| **RF1.d** (Manejo sesiones) | `server.py` | Generación `session_token` en `/login` |
| **RF2** (Transacciones JSON) | `server.py` | Ruta `@app.post("/api/v1/transfer")`, validación Pydantic |
| **RS1.a** (Derivación robusta/Salt) | `server.py` | Uso de `bcrypt.hashpw` con salt embebido. |
| **RS1.b** (Protección fuerza bruta) | `server.py` | Lógica `failed_attempts` y `locked_until` en `/login` |
| **RS2** (Integridad y MAC) | `server.py` | Generación y validación de `hmac.new()` en `/transfer` |
| **RS3.a** (Nonce y Timestamps) | `server.py` / `index.html` | Cabeceras `X-Nonce` y `X-Timestamp` |
| **RS3.b** (Tabla de NONCEs) | `server.py` | Inserción y validación en tabla `nonces` (DB SQLite) |
| **RS4** (Tiempo constante) | `server.py` | `bcrypt.checkpw()` en `/login` y `hmac.compare_digest()` en `/transfer` |

## 7. Justificación de Herramientas de IA Generativa

Se han empleado modelos de lenguaje (LLM) como asistentes durante el desarrollo del proyecto para las siguientes tareas específicas:

*   **Refactorización de Código:** Migración guiada del esquema inicial basado en `PBKDF2-HMAC-SHA256` al estándar moderno `bcrypt` para cumplir con las mejores prácticas actuales de derivación de claves.
*   **Desarrollo Frontend:** Generación de la estructura base y estilos de la interfaz de usuario web (`index.html`), integrando las llamadas a la API mediante `fetch`.
*   **Diseño de Pruebas Estadísticas:** Implementación de la metodología de evaluación (t-test de Welch) en el script de cliente para el análisis estadístico de los ataques de canal lateral (*Timing Attacks*), garantizando la fiabilidad de las mediciones (intercalado de muestras y descarte de tiempos de calentamiento).

Todos los controles de seguridad y conceptos criptográficos (comparación constante, gestión de nonces y firmas MAC) fueron comprendidos, validados y ajustados manualmente para cumplir estrictamente con los requerimientos del PAI.
