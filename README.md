# PAI-2: BYODSEC - Bring Your Own Device Seguro (VPN TLS)

Este proyecto implementa una infraestructura de red segura (VPN a nivel de aplicación) utilizando Sockets y el protocolo **TLS 1.3 con Autenticación Mutua (mTLS)** para satisfacer los requisitos del proyecto PAI-2 (BYODSEC).

## Estructura del Proyecto

* `pki/` - Infraestructura de Clave Pública. Contiene el script para generar la CA, los certificados de servidor y de los clientes pre-cargados.
* `server/` - Servidor VPN. Gestiona las conexiones entrantes, valida mTLS y las credenciales.
* `client/` - Cliente VPN y script de Benchmark.

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
3. Introduce `pdi_user` y `pdi_password123`.
4. Haz clic en "Iniciar Sesión Segura". El portal cargará automáticamente el certificado mTLS del usuario y establecerá el túnel VPN.

### Opción B: Cliente de Consola (CLI)
1. En otra terminal, ejecuta:
   ```bash
   python client/client.py -u pdi_user -p pdi_password123
   ```
2. Una vez conectado, el canal se establecerá y podrás enviar mensajes por el túnel cifrado.
3. Para cerrar la sesión y desmontar el túnel de forma segura, escribe `LOGOUT`.

## Paso 4: Registro de Nuevos Usuarios (RF1)
Para cumplir con el requisito de registro y emparejamiento BYOD:
1. Ejecuta el script de registro:
   ```bash
   python server/register_user.py
   ```
2. Introduce un nuevo nombre de usuario, contraseña y rol.
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
Podrás comparar el tiempo total de ejecución y evaluar el sobrecoste (overhead) que introduce el cifrado mTLS.

## Paso 6: Generar Evidencias para la Entrega (.pcap y Logs)
1. **Auditoría (RS4):** El servidor genera automáticamente un registro de todas las conexiones, intentos fallidos y desconexiones en el archivo `server/audit.log`.
2. **PCAP:** Abre Wireshark (o tcpdump), selecciona la interfaz Loopback, filtra por `tcp.port == 8443`, captura el tráfico conectando un cliente, detén la captura y guárdalo como `evidencia_tls13.pcap`.

## Paso 7 (Extra +10%): Simulación de Ataque Interceptador (MITM)
El proyecto incluye un script para demostrar empíricamente cómo la arquitectura VPN TLS resiste intentos de lectura de tráfico.
1. Ejecuta el sniffer: `python extra_mitm.py`
2. En el cliente conéctate por el MITM: `python client/client.py -u pdi_user -p pdi_password123 --port 8444`.
3. Observa en la consola del MITM cómo los paquetes viajan cifrados e ilegibles, y cómo no puede descifrar las credenciales de la capa de aplicación.

## Paso 8: Generación del Entregable `PAI2-STX.zip`
1. Añade tu informe PDF (`Documento PDF - máximo 15 páginas`).
2. Añade los ficheros `.pcap` de las capturas de red y el archivo `audit.log`.
3. Comprime todo el directorio (Código fuente + PKI + Logs + Documentación).
4. Súbelo a Blackboard antes de la fecha límite (27 de octubre).

### Extra: suplantación del servidor
`python extra_rogue_server.py` levanta un servidor impostor (puerto 8445) con un certificado emitido por **otra** CA.
`python client/client.py -u pdi_user -p pdi_password123 --port 8445` debe fallar con `CERTIFICATE_VERIFY_FAILED`.

## Pruebas automáticas
```bash
python -m unittest discover -s tests -v
```
Arrancan el servidor, y comprueban: login legítimo, certificado de otro usuario (suplantación), cliente sin certificado,
servidor con CA falsa, TLS 1.2 rechazado, cliente colgado sin bloquear el servidor, bloqueo por intentos fallidos y
entradas en `audit.log`.

## Cambios de seguridad añadidos
* El CN del certificado de cliente debe coincidir con el usuario que hace login.
* Handshake mTLS en el hilo del cliente y con timeouts; los rechazos se registran en `audit.log`.
* Solo se aceptan `TLS_AES_256_GCM_SHA384` y `TLS_CHACHA20_POLY1305_SHA256`.
* Bloqueo temporal tras 5 intentos fallidos; saneado de logs.
* Contraseñas con PBKDF2-HMAC-SHA256 (200.000 iteraciones) + sal. Si vienes de la versión anterior: borra `users.db`,
  renombra `users.json.migrated` a `users.json` y ejecuta `python server/migrate_users.py`.
