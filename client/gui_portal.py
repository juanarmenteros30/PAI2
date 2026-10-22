import tkinter as tk
from tkinter import messagebox, scrolledtext
import socket
import ssl
import json
import os
import queue
import threading

# Configuración por defecto
HOST = 'localhost'
PORT = 8443
CERTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'pki', 'certs')
CA_CERT = os.path.join(CERTS_DIR, 'ca-cert.pem')

class VPNPortal(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("U-Secure - Portal de Acceso BYOD")
        self.geometry("450x500")
        self.configure(bg="#f0f0f0")
        self.secure_sock = None
        self.connected = False
        
        # Los hilos de red NUNCA tocan Tk: encolan funciones que ejecuta el hilo principal
        self._ui_queue = queue.Queue()
        self.create_widgets()
        self.after(50, self._drain_ui_queue)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        
    def create_widgets(self):
        # Header
        header = tk.Label(self, text="U-Secure VPN", font=("Helvetica", 18, "bold"), bg="#004aad", fg="white", pady=10)
        header.pack(fill=tk.X)
        
        # Login Frame
        self.login_frame = tk.Frame(self, bg="#f0f0f0", pady=20)
        self.login_frame.pack(fill=tk.X, padx=20)
        
        tk.Label(self.login_frame, text="Usuario Corporativo:", bg="#f0f0f0", font=("Helvetica", 10)).pack(anchor="w")
        self.user_entry = tk.Entry(self.login_frame, font=("Helvetica", 12))
        self.user_entry.pack(fill=tk.X, pady=5)
        
        tk.Label(self.login_frame, text="Contraseña:", bg="#f0f0f0", font=("Helvetica", 10)).pack(anchor="w")
        self.pass_entry = tk.Entry(self.login_frame, font=("Helvetica", 12), show="*")
        self.pass_entry.pack(fill=tk.X, pady=5)
        
        self.connect_btn = tk.Button(self.login_frame, text="Iniciar Sesión Segura (mTLS)", font=("Helvetica", 12, "bold"), bg="#004aad", fg="white", command=self.connect_vpn)
        self.connect_btn.pack(fill=tk.X, pady=15)
        
        # Status/Chat Frame
        self.status_frame = tk.Frame(self, bg="#f0f0f0")
        self.status_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=5)
        
        tk.Label(self.status_frame, text="Consola de la VPN:", bg="#f0f0f0", font=("Helvetica", 10, "bold")).pack(anchor="w")
        
        self.log_area = scrolledtext.ScrolledText(self.status_frame, wrap=tk.WORD, height=10, font=("Consolas", 9))
        self.log_area.pack(fill=tk.BOTH, expand=True)
        self.log_area.config(state=tk.DISABLED)
        
        # Input Frame (para enviar comandos)
        self.input_frame = tk.Frame(self, bg="#f0f0f0", pady=10)
        self.input_frame.pack(fill=tk.X, padx=20)
        
        self.msg_entry = tk.Entry(self.input_frame, font=("Helvetica", 11), state=tk.DISABLED)
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.msg_entry.bind("<Return>", lambda e: self.send_message())
        
        self.send_btn = tk.Button(self.input_frame, text="Enviar", state=tk.DISABLED, command=self.send_message)
        self.send_btn.pack(side=tk.RIGHT)
        
    def run_ui(self, fn, *args):
        """Seguro desde cualquier hilo: ejecuta fn(*args) en el hilo principal de Tk."""
        self._ui_queue.put((fn, args))

    def _drain_ui_queue(self):
        try:
            while True:
                fn, args = self._ui_queue.get_nowait()
                fn(*args)
        except queue.Empty:
            pass
        self.after(50, self._drain_ui_queue)

    def log(self, message):
        self.run_ui(self._log, message)

    def _log(self, message):
        self.log_area.config(state=tk.NORMAL)
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)
        self.log_area.config(state=tk.DISABLED)
        
    def connect_vpn(self):
        if self.connected:
            self.disconnect_vpn()
            return
            
        username = self.user_entry.get().strip()
        password = self.pass_entry.get()      # sin strip: la contraseña puede llevar espacios
        
        if not username or not password:
            messagebox.showerror("Error", "Por favor, introduce usuario y contraseña.")
            return
            
        client_cert = os.path.join(CERTS_DIR, f"{username}-cert.pem")
        client_key = os.path.join(CERTS_DIR, f"{username}-key.pem")
        
        if not os.path.exists(client_cert) or not os.path.exists(client_key):
            messagebox.showerror("Error de Certificado", f"No se encuentran certificados mTLS para el usuario '{username}'.")
            return
            
        self.connect_btn.config(state=tk.DISABLED, text="Conectando...")
        self.log(f"[*] Iniciando Handshake mTLS (TLS 1.3)...")
        
        threading.Thread(target=self._connection_thread, args=(username, password, client_cert, client_key), daemon=True).start()
        
    def _connection_thread(self, username, password, client_cert, client_key):
        sock = None
        try:
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.load_cert_chain(certfile=client_cert, keyfile=client_key)

            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(10)                      # conexión + handshake no se cuelgan
            sock = context.wrap_socket(raw, server_hostname=HOST)
            sock.connect((HOST, PORT))

            self.log(f"[*] Cifrado establecido: {sock.cipher()[0]}")
            self.log(f"[*] Enviando credenciales para {username}...")

            sock.sendall(json.dumps({"username": username, "password": password}).encode('utf-8'))
            auth_response = sock.recv(1024).decode('utf-8', errors='replace')

            if auth_response.startswith("OK"):
                sock.settimeout(None)
                self.secure_sock = sock
                self.connected = True
                self.log("\n[OK] TÚNEL VPN ESTABLECIDO CON ÉXITO")
                self.run_ui(self._update_ui_connected)
                threading.Thread(target=self._receive_thread, args=(sock,), daemon=True).start()
            else:
                self.log(f"[X] Error de autenticación: {auth_response.strip()}")
                sock.close()
                self.run_ui(self._update_ui_disconnected)

        except ssl.SSLError as e:
            self.log(f"[X] Error de seguridad mTLS: {e}")
            if sock:
                sock.close()
            self.run_ui(self._update_ui_disconnected)
        except Exception as e:
            self.log(f"[X] Error de red: {e}")
            if sock:
                sock.close()
            self.run_ui(self._update_ui_disconnected)

    def _update_ui_connected(self):
        self.connect_btn.config(state=tk.NORMAL, text="Cerrar Sesión (LOGOUT)", bg="#d9534f")
        self.user_entry.config(state=tk.DISABLED)
        self.pass_entry.config(state=tk.DISABLED)
        self.msg_entry.config(state=tk.NORMAL)
        self.send_btn.config(state=tk.NORMAL)
        
    def _update_ui_disconnected(self):
        self.connect_btn.config(state=tk.NORMAL, text="Iniciar Sesión Segura (mTLS)", bg="#004aad")
        self.user_entry.config(state=tk.NORMAL)
        self.pass_entry.config(state=tk.NORMAL)
        self.msg_entry.config(state=tk.DISABLED)
        self.send_btn.config(state=tk.DISABLED)
        
    def disconnect_vpn(self):
        sock = self.secure_sock
        if not sock:
            self._finish_disconnect()
            return
        self.log("[*] Desmontando el túnel seguro y cerrando sesión...")
        self.connect_btn.config(state=tk.DISABLED)
        try:
            # El servidor responde y cierra; el hilo receptor detecta el EOF y termina el cierre
            sock.sendall(b"LOGOUT")
            self.after(3000, lambda: self._finish_disconnect(sock))   # salvaguarda
        except Exception:
            self._finish_disconnect(sock)

    def _finish_disconnect(self, expected=None):
        """Cierra el socket y restaura la UI. `expected` evita cerrar una sesión posterior."""
        if expected is not None and self.secure_sock is not expected:
            return
        sock, self.secure_sock = self.secure_sock, None
        self.connected = False
        if sock:
            try:
                sock.close()
            except Exception:
                pass
        self._update_ui_disconnected()

    def _receive_thread(self, sock):
        try:
            while self.secure_sock is sock:
                data = sock.recv(1024)
                if not data:
                    break
                self.log(f"[SERVER] {data.decode('utf-8', errors='replace').strip()}")
        except Exception:
            pass
        finally:
            self.run_ui(self._finish_disconnect, sock)

    def on_close(self):
        """Al cerrar la ventana se cierra la sesión VPN de forma ordenada."""
        sock = self.secure_sock
        if sock:
            try:
                sock.sendall(b"LOGOUT")      # el servidor cierra su lado; luego cerramos el nuestro
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass
        self.destroy()

    def send_message(self):
        if not self.connected: return
        msg = self.msg_entry.get().strip()
        if not msg: return
        
        self.msg_entry.delete(0, tk.END)
        self.log(f"Tú: {msg}")
        
        try:
            self.secure_sock.sendall(msg.encode('utf-8'))
        except Exception as e:
            self.log(f"[X] Error al enviar: {e}")
            self._finish_disconnect()

if __name__ == "__main__":
    app = VPNPortal()
    app.mainloop()
