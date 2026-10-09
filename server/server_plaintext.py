import socket
import threading
import json
import os

HOST = '0.0.0.0'
PORT = 8080
USERS_FILE = os.path.join(os.path.dirname(__file__), 'users.json')

def load_users():
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def handle_client(conn, addr, users):
    try:
        auth_data = conn.recv(1024).decode('utf-8')
        if not auth_data: return
            
        try:
            credentials = json.loads(auth_data)
            username = credentials.get('username')
            password = credentials.get('password')
        except:
            conn.sendall(b"ERROR\n")
            return
            
        if username in users and users[username]['password'] == password:
            conn.sendall(b"OK\n")
            while True:
                data = conn.recv(4096)
                if not data: break
                if data.decode('utf-8').strip() == "LOGOUT":
                    conn.sendall(b"BYE\n")
                    break
                conn.sendall(b"ACK\n")
        else:
            conn.sendall(b"ERROR\n")
    except Exception as e:
        pass
    finally:
        conn.close()

def start_server():
    users = load_users()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(350)
    
    print(f"[*] Servidor NO CIFRADO (Plaintext) escuchando en {HOST}:{PORT}")
    try:
        while True:
            client_sock, addr = server_socket.accept()
            t = threading.Thread(target=handle_client, args=(client_sock, addr, users))
            t.daemon = True
            t.start()
    except KeyboardInterrupt:
        pass
    finally:
        server_socket.close()

if __name__ == '__main__':
    start_server()
