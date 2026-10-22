# PAI-2: BYODSEC - Bring Your Own Device Seguro (VPN TLS)

Este proyecto implementa una infraestructura de red segura (VPN a nivel de aplicación) utilizando Sockets y el protocolo **TLS 1.3 con Autenticación Mutua (mTLS)** para satisfacer los requisitos del proyecto PAI-2 (BYODSEC).

## Estructura del Proyecto

* `pki/` - Infraestructura de Clave Pública. Contiene el script para generar la CA, los certificados de servidor y de los clientes pre-cargados.
* `server/` - Servidor VPN (mTLS + credenciales en SQLite con PBKDF2), servidor sin cifrar para comparar, registro de usuarios y `seed_users.py`.
* `client/` - Cliente de consola, portal gráfico y scripts de benchmark.
* `tests/` - Pruebas automáticas de seguridad.
* `extra_mitm.py`, `extra_rogue_server.py` - Demostraciones de interceptación y suplantación.

## Requisitos Previos

Necesitas Python 3.10+ instalado en tu sistema.

1. Instala las dependencias necesarias:
   ```bash
   pip install -r requirements.txt
   ```

## Paso 1: Generar la PKI y Certificados

El sistema requiere certificados digitales X.509 tanto para el servidor como para los clientes (mTLS).

1. Navega a la carpeta del proyecto.
2. Ejecuta el generador de PKI:
   ```bash
   python pki/generate_pki.py
   ```
   *Esto generará la CA (Root), el certificado del servidor, y los certificados para los usuarios precargados (`pdi_user`, `pas_user`, `inv_user`) en la carpeta `pki/certs/`.*
   Si ya existe una PKI, el script se niega a sobrescribirla (invalidaría todos los certificados emitidos); usa `--force` solo si de verdad quieres rehacerla.
3. Crea los usuarios precargados en la base de datos (idempotente, no toca los que ya existan):
   ```bash
   python server/seed_users.py
   ```

## Paso 2: Iniciar el Servidor VPN

El servidor cargará la CA, su certificado y forzará mTLS y TLS 1.3.

1. En una terminal nueva, ejecuta:
   ```bash
   python server/server.py
   ```
   *Verás que el servidor inicia y queda a la escucha en el puerto 8443.*

## Paso 3: Conectar a un Cliente

El cliente enviará su certificado, validará el servidor e iniciará sesión con su usuario y contraseña (doble capa de seguridad).

### Opción A: Portal Gráfico (GUI)
He añadido un portal con interfaz gráfica (`tkinter`) para que sea más fácil iniciar sesión y hacer pruebas visuales del proyecto.

1. Ejecuta el portal:
   ```bash
   python client/gui_portal.py
   ```
2. Aparecerá una ventana de inicio de sesión con los campos "Usuario" y "Contraseña".
3. Introduce `pdi_user` y `pdi_password123` (usuarios de demostración de la práctica).
4. Haz clic en "Iniciar Sesión Segura". El portal cargará automáticamente el certificado mTLS del usuario y establecerá el túnel VPN.

### Opción B: Cliente de Consola (CLI)
1. En otra terminal, ejecuta:
   ```bash
   python client/client.py -u pdi_user
   ```
   La contraseña se pide por teclado sin mostrarla (también puedes pasarla con `-p`, aunque quedaría en el historial del terminal).
2. Una vez conectado, el canal se establecerá y podrás enviar mensajes por el túnel cifrado.
3. Para cerrar la sesión y desmontar el túnel de forma segura, escribe `LOGOUT`.

## Paso 4: Registro de Nuevos Usuarios (RF1)
Para cumplir con el requisito de registro y emparejamiento BYOD:
1. Ejecuta el script de registro:
   ```bash
   python server/register_user.py
   ```
2. Introduce un nuevo nombre de usuario (3-32 caracteres: a-z, 0-9, `_`), contraseña (mínimo 8 caracteres, se pide dos veces) y rol.
3. El sistema solicitará la emisión de su certificado a la CA, lo guardará en `pki/certs/` y lo registrará en la base de datos corporativa. Tras esto, podrás entrar al portal GUI con ese nuevo usuario.

## Paso 5: Pruebas de Carga y Rendimiento (Benchmarking)
El proyecto incluye scripts para evaluar el comportamiento del servidor ante 300 conexiones concurrentes, comparando cuantitativamente el tráfico cifrado (VPN TLS) frente al tráfico no cifrado.

**Prueba Cifrada (VPN TLS 1.3 con mTLS):**
1. Asegúrate de tener el servidor seguro corriendo (`python server/server.py`).
2. Ejecuta el test de estrés seguro:
   ```bash
   python client/benchmark.py
   ```

**Prueba No Cifrada (Plaintext - Para comparación):**
1. En otra terminal, ejecuta el servidor sin cifrado:
   ```bash
   python server/server_plaintext.py
   ```
2. Ejecuta el test de estrés no cifrado:
   ```bash
   python client/benchmark_plaintext.py
   ```

Opciones de ambos scripts: `--clients N` (por defecto 300), `--ramp SEGUNDOS` (escalona el inicio de los clientes) y
`--pid PID_DEL_SERVIDOR` (mide CPU y RAM del servidor; requiere `psutil`).
Cada ejecución imprime media, p50, p95 y máximo del tiempo de handshake/conexión, del login y del RTT por mensaje,
más el throughput, y guarda el detalle en `benchmark_tls.csv` / `benchmark_plaintext.csv`.
Ten en cuenta que el login incluye el coste de PBKDF2 (200.000 iteraciones, ~0,15 s de CPU por verificación), que es
igual en ambos servidores: el sobrecoste de TLS se ve en las columnas de handshake y RTT.

## Paso 6: Generar Evidencias para la Entrega (.pcap y Logs)
1. **Auditoría (RS4):** El servidor genera automáticamente un registro (UTF-8) de las conexiones, los handshakes rechazados, los intentos fallidos, los intentos de suplantación y las desconexiones en `server/audit.log`.
2. **PCAP:** Abre Wireshark (o tcpdump), selecciona la interfaz Loopback, filtra por `tcp.port == 8443`, captura el tráfico conectando un cliente, detén la captura y guárdalo como `evidencia_tls13.pcap`.

## Paso 7 (Extra +10%): Simulación de Ataque Interceptador (MITM)
El proyecto incluye un script para demostrar empíricamente cómo la arquitectura VPN TLS resiste intentos de lectura de tráfico.
1. Ejecuta el sniffer: `python extra_mitm.py` (opciones `--listen` y `--target` para cambiar los puertos).
2. En el cliente conéctate por el MITM: `python client/client.py -u pdi_user --port 8444`.
3. Observa en la consola del MITM cómo los paquetes viajan cifrados e ilegibles, y cómo no puede descifrar las credenciales de la capa de aplicación.

## Paso 8: Generación del Entregable `PAI2-STX.zip`
1. Añade tu informe PDF (`Documento PDF - máximo 15 páginas`).
2. Añade los ficheros `.pcap` de las capturas de red y el archivo `audit.log`.
3. Comprime todo el directorio (Código fuente + PKI + Logs + Documentación).
4. Súbelo a Blackboard antes de la fecha límite (27 de octubre).

### Extra: suplantación del servidor
`python extra_rogue_server.py` levanta un servidor impostor (puerto 8445) con un certificado emitido por **otra** CA.
`python client/client.py -u pdi_user --port 8445` debe fallar con `CERTIFICATE_VERIFY_FAILED`.

## Pruebas automáticas
```bash
python -m unittest discover -s tests -v
```
Preparan el entorno (generan la PKI si falta y crean los usuarios precargados), arrancan el servidor real y comprueban:
login legítimo con TLS 1.3 y cipher AEAD, certificado de otro usuario (suplantación), cliente sin certificado,
servidor con CA falsa, TLS 1.2 rechazado, cliente colgado sin bloquear el servidor, registro de usuarios (RF1),
bloqueo por intentos fallidos y entradas en `audit.log`. Para incluir la prueba de la interfaz gráfica
(necesita pantalla): `set PAI2_GUI_TEST=1` (Windows) o `PAI2_GUI_TEST=1` (Linux/macOS) antes de ejecutarlas.
Cierra cualquier servidor que tengas abierto en el puerto 8443 antes de lanzarlas.

## Medidas de seguridad implementadas
* TLS 1.3 obligatorio y autenticación mutua (mTLS) con CA corporativa propia.
* El CN del certificado de cliente debe coincidir con el usuario que hace login (evita usar el certificado de otro).
* Solo se aceptan `TLS_AES_256_GCM_SHA384` y `TLS_CHACHA20_POLY1305_SHA256` (Python no permite fijar las suites de TLS 1.3, por eso se comprueban tras el handshake).
* Handshake dentro del hilo de cada cliente y con timeouts (un cliente lento o colgado no bloquea al resto); tope de 500 conexiones simultáneas.
* Bloqueo temporal tras 5 intentos fallidos; los datos que llegan al log se sanean (sin inyección de líneas).
* Contraseñas con PBKDF2-HMAC-SHA256 (200.000 iteraciones) + sal de 32 bytes, y verificación que tarda lo mismo exista o no el usuario.
* Claves privadas con permisos 600 en sistemas POSIX; la regeneración de la PKI requiere `--force`.

Limitaciones conocidas: no hay revocación de certificados (CRL/OCSP); las claves privadas de los clientes están en disco sin cifrar y en la misma carpeta que las del servidor (en un despliegue real cada dispositivo guardaría solo la suya y la CA estaría aislada).
