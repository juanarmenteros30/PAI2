import socket
import json
import threading
import time

HOST = 'localhost'
PORT = 8080

successful_connections = 0
failed_connections = 0
lock = threading.Lock()

def plaintext_client_worker(client_id):
    global successful_connections, failed_connections
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((HOST, PORT))
        
        credentials = {"username": "pdi_user", "password": "pdi_password123"}
        sock.sendall(json.dumps(credentials).encode('utf-8'))
        
        auth_response = sock.recv(1024).decode('utf-8')
        if "OK" in auth_response:
            with lock:
                successful_connections += 1
            
            for _ in range(5):
                sock.sendall(b"BENCHMARK_DATA\n")
                sock.recv(1024)
                time.sleep(1)
            
            sock.sendall(b"LOGOUT")
            sock.recv(1024)
            
    except Exception as e:
        with lock:
            failed_connections += 1

def run_benchmark(num_clients):
    print(f"[*] Iniciando prueba de carga (NO CIFRADA) con {num_clients} usuarios...")
    threads = []
    start_time = time.time()
    
    for i in range(num_clients):
        t = threading.Thread(target=plaintext_client_worker, args=(i,))
        threads.append(t)
        t.start()
        
    for t in threads:
        t.join()
        
    end_time = time.time()
    
    print("\n--- RESULTADOS DEL BENCHMARK (Plaintext) ---")
    print(f"Conexiones exitosas: {successful_connections}")
    print(f"Conexiones fallidas: {failed_connections}")
    print(f"Tiempo total: {end_time - start_time:.2f} segundos")

if __name__ == '__main__':
    run_benchmark(300)
