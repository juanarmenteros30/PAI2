import socket
import ssl
import json
import os
import threading
import time

HOST = 'localhost'
PORT = 8443
CERTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'pki', 'certs')
CA_CERT = os.path.join(CERTS_DIR, 'ca-cert.pem')
CLIENT_CERT = os.path.join(CERTS_DIR, 'pdi_user-cert.pem')
CLIENT_KEY = os.path.join(CERTS_DIR, 'pdi_user-key.pem')

# Estadísticas
successful_connections = 0
failed_connections = 0
lock = threading.Lock()

def vpn_client_worker(client_id):
    global successful_connections, failed_connections
    
    try:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
        
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        secure_sock = context.wrap_socket(client_socket, server_hostname=HOST)
        secure_sock.connect((HOST, PORT))
        
        # Enviar credenciales
        credentials = {"username": "pdi_user", "password": "pdi_password123"}
        secure_sock.sendall(json.dumps(credentials).encode('utf-8'))
        
        # Validar login
        auth_response = secure_sock.recv(1024).decode('utf-8')
        if "OK" in auth_response:
            with lock:
                successful_connections += 1
            
            # Mantener la conexión viva y enviar algunos paquetes
            for _ in range(5):
                secure_sock.sendall(b"BENCHMARK_DATA\n")
                secure_sock.recv(1024)
                time.sleep(1)
            
            # Cierre seguro
            secure_sock.sendall(b"LOGOUT")
            secure_sock.recv(1024)
            
    except Exception as e:
        with lock:
            failed_connections += 1
        # print(f"Error client {client_id}: {e}")

def run_benchmark(num_clients):
    print(f"[*] Iniciando prueba de carga con {num_clients} usuarios concurrentes...")
    threads = []
    start_time = time.time()
    
    for i in range(num_clients):
        t = threading.Thread(target=vpn_client_worker, args=(i,))
        threads.append(t)
        t.start()
        
    for t in threads:
        t.join()
        
    end_time = time.time()
    
    print("\n--- RESULTADOS DEL BENCHMARK ---")
    print(f"Conexiones exitosas: {successful_connections}")
    print(f"Conexiones fallidas: {failed_connections}")
    print(f"Tiempo total: {end_time - start_time:.2f} segundos")

if __name__ == '__main__':
    run_benchmark(300)
