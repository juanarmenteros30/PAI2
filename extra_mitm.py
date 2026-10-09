import socket
import threading
import sys

# Configuración del proxy MITM
LISTEN_HOST = '127.0.0.1'
LISTEN_PORT = 8444  # El cliente se conectará aquí
TARGET_HOST = '127.0.0.1'
TARGET_PORT = 8443  # Servidor real

def hex_dump(data):
    return ' '.join(f'{b:02x}' for b in data)

def forward(source, destination, direction):
    try:
        while True:
            data = source.recv(4096)
            if not data:
                break
            print(f"\n[MITM] Tráfico interceptado ({direction}) - {len(data)} bytes")
            print(f"Contenido (Hex): {hex_dump(data[:64])}...")
            
            # Intento de leer texto claro (fallará porque es TLS 1.3)
            try:
                text = data.decode('utf-8')
                print(f"Texto Claro: {text}")
            except:
                print("Texto Claro: [ILEGIBLE / CIFRADO]")
                
            destination.sendall(data)
    except Exception as e:
        pass
    finally:
        source.close()
        destination.close()

def start_mitm():
    mitm_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mitm_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mitm_socket.bind((LISTEN_HOST, LISTEN_PORT))
    mitm_socket.listen(5)
    
    print(f"[*] MITM Sniffer escuchando en {LISTEN_HOST}:{LISTEN_PORT}")
    print(f"[*] Reenviando tráfico hacia {TARGET_HOST}:{TARGET_PORT}")
    print("[*] (Extra opcional: Demostración de protección frente a interceptación)")
    
    try:
        while True:
            client_sock, addr = mitm_socket.accept()
            print(f"\n[!] Nueva víctima conectada desde {addr}")
            
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.connect((TARGET_HOST, TARGET_PORT))
            
            # Hilos para reenviar en ambas direcciones
            threading.Thread(target=forward, args=(client_sock, server_sock, "Cliente -> Servidor"), daemon=True).start()
            threading.Thread(target=forward, args=(server_sock, client_sock, "Servidor -> Cliente"), daemon=True).start()
            
    except KeyboardInterrupt:
        print("\n[*] Apagando atacante MITM...")
    finally:
        mitm_socket.close()

if __name__ == '__main__':
    start_mitm()
