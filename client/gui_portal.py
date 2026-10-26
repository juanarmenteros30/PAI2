import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import socket
import ssl
import json
import os
import queue
import threading
from datetime import datetime

# Configuración por defecto
HOST      = 'localhost'
PORT      = 8443
REG_PORT  = 8446          # Puerto del servidor de auto-registro (TLS sin mTLS)
CERTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'pki', 'certs')
CA_CERT   = os.path.join(CERTS_DIR, 'ca-cert.pem')


class VPNPortal(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("U-Secure - Portal de Acceso BYOD")
        self.geometry("520x680")
        self.minsize(420, 560)
        self.configure(bg="#1e1e2e")
        self.secure_sock = None
        self.connected   = False
        self._username   = ""

        # Los hilos de red NUNCA tocan Tk: encolan funciones que ejecuta el hilo principal
        self._ui_queue = queue.Queue()
        self._build_ui()
        self.after(50, self._drain_ui_queue)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    # ─────────────────────────────────────────────────────────────────────────
    #  Construcción de la interfaz
    # ─────────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Header ────────────────────────────────────────────────────────────
        header = tk.Frame(self, bg="#004aad")
        header.pack(fill=tk.X)
        tk.Label(
            header, text="🔒  U-Secure VPN", font=("Helvetica", 16, "bold"),
            bg="#004aad", fg="white", pady=10, padx=14
        ).pack(side=tk.LEFT)
        self._status_lbl = tk.Label(
            header, text="● Desconectado", font=("Helvetica", 9),
            bg="#004aad", fg="#ff6b6b", pady=10, padx=10
        )
        self._status_lbl.pack(side=tk.RIGHT)

        # ── Notebook (login / registro) ────────────────────────────────────────
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook", background="#1e1e2e", borderwidth=0)
        style.configure("TNotebook.Tab", background="#2a2a3e", foreground="#aaaacc",
                        padding=[12, 6], font=("Helvetica", 9))
        style.map("TNotebook.Tab",
                  background=[("selected", "#004aad")],
                  foreground=[("selected", "white")])

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.X, padx=10, pady=(8, 0))
        self._build_login_tab()
        self._build_register_tab()

        # ── Separador ─────────────────────────────────────────────────────────
        tk.Frame(self, bg="#2a2a3e", height=1).pack(fill=tk.X, padx=10, pady=(8, 0))

        # ── Área de CHAT (visible siempre, activa tras conectar) ───────────────
        chat_outer = tk.Frame(self, bg="#1e1e2e")
        chat_outer.pack(fill=tk.BOTH, expand=True, padx=10, pady=(6, 0))

        chat_header = tk.Frame(chat_outer, bg="#2a2a3e")
        chat_header.pack(fill=tk.X)
        tk.Label(
            chat_header, text="💬  Mensajes", font=("Helvetica", 9, "bold"),
            bg="#2a2a3e", fg="#aaaacc", pady=4, padx=8
        ).pack(side=tk.LEFT)
        self._conn_badge = tk.Label(
            chat_header, text="Inicia sesión para chatear",
            font=("Helvetica", 8), bg="#2a2a3e", fg="#666688", padx=8
        )
        self._conn_badge.pack(side=tk.RIGHT)

        # Área de mensajes con tags de color
        self.chat_area = tk.Text(
            chat_outer, wrap=tk.WORD, state=tk.DISABLED,
            bg="#12121e", fg="#e0e0ff", font=("Consolas", 10),
            relief=tk.FLAT, padx=8, pady=6, cursor="arrow",
            selectbackground="#2a2a3e"
        )
        self.chat_area.pack(fill=tk.BOTH, expand=True)

        # Scrollbar para el chat
        scroll = tk.Scrollbar(self.chat_area, command=self.chat_area.yview,
                              bg="#2a2a3e", troughcolor="#12121e")
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.chat_area.config(yscrollcommand=scroll.set)

        # Tags de color para el chat
        self.chat_area.tag_config("mine",    foreground="#7ec8e3", justify="right")
        self.chat_area.tag_config("server",  foreground="#90ee90")
        self.chat_area.tag_config("system",  foreground="#888899", font=("Consolas", 8))
        self.chat_area.tag_config("error",   foreground="#ff6b6b")
        self.chat_area.tag_config("time",    foreground="#555577", font=("Consolas", 7))
        self.chat_area.tag_config("ok",      foreground="#00cc66", font=("Consolas", 9, "bold"))

        # ── Campo de escritura ─────────────────────────────────────────────────
        input_outer = tk.Frame(self, bg="#2a2a3e", pady=6)
        input_outer.pack(fill=tk.X, padx=10, pady=(4, 0))

        self.msg_entry = tk.Entry(
            input_outer, font=("Helvetica", 11), state=tk.DISABLED,
            bg="#12121e", fg="#e0e0ff", insertbackground="white",
            relief=tk.FLAT, disabledbackground="#1e1e2e",
            disabledforeground="#444466"
        )
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 6), ipady=5)
        self.msg_entry.bind("<Return>", lambda e: self.send_message())
        self.msg_entry.insert(0, "Conéctate para poder enviar mensajes…")

        self.send_btn = tk.Button(
            input_outer, text="Enviar ➤", state=tk.DISABLED,
            font=("Helvetica", 10, "bold"), bg="#004aad", fg="white",
            relief=tk.FLAT, padx=12, pady=5, cursor="arrow",
            activebackground="#0062d8", activeforeground="white",
            command=self.send_message
        )
        self.send_btn.pack(side=tk.RIGHT, padx=(0, 8))

        # ── Log de sistema (colapsado, pequeño) ───────────────────────────────
        sys_frame = tk.Frame(self, bg="#1e1e2e")
        sys_frame.pack(fill=tk.X, padx=10, pady=(4, 6))

        tk.Label(
            sys_frame, text="▸ Log del sistema", font=("Helvetica", 7, "bold"),
            bg="#1e1e2e", fg="#555577", cursor="hand2"
        ).pack(anchor="w")

        self.log_area = scrolledtext.ScrolledText(
            sys_frame, wrap=tk.WORD, height=3, font=("Consolas", 7),
            bg="#0a0a14", fg="#555577", relief=tk.FLAT,
            state=tk.DISABLED
        )
        self.log_area.pack(fill=tk.X)

    def _build_login_tab(self):
        """Pestaña de inicio de sesión."""
        frame = tk.Frame(self.notebook, bg="#1e1e2e", pady=10)
        self.notebook.add(frame, text="  Iniciar Sesión  ")

        tk.Label(frame, text="Usuario Corporativo:", bg="#1e1e2e",
                 fg="#aaaacc", font=("Helvetica", 9)).pack(anchor="w", padx=14)
        self.user_entry = tk.Entry(
            frame, font=("Helvetica", 12), bg="#12121e", fg="#e0e0ff",
            insertbackground="white", relief=tk.FLAT
        )
        self.user_entry.pack(fill=tk.X, padx=14, pady=(2, 8), ipady=4)

        tk.Label(frame, text="Contraseña:", bg="#1e1e2e",
                 fg="#aaaacc", font=("Helvetica", 9)).pack(anchor="w", padx=14)
        self.pass_entry = tk.Entry(
            frame, font=("Helvetica", 12), show="•", bg="#12121e", fg="#e0e0ff",
            insertbackground="white", relief=tk.FLAT
        )
        self.pass_entry.pack(fill=tk.X, padx=14, pady=(2, 10), ipady=4)

        self.connect_btn = tk.Button(
            frame, text="🔐  Iniciar Sesión Segura (mTLS)",
            font=("Helvetica", 11, "bold"), bg="#004aad", fg="white",
            relief=tk.FLAT, pady=8, activebackground="#0062d8",
            activeforeground="white", command=self.connect_vpn
        )
        self.connect_btn.pack(fill=tk.X, padx=14, pady=(0, 6))

        tk.Label(
            frame,
            text="¿Aún no tienes credenciales? Ve a la pestaña «Solicitar Acceso».",
            bg="#1e1e2e", fg="#555577", font=("Helvetica", 8), wraplength=400
        ).pack(padx=14, pady=(2, 0))

    def _build_register_tab(self):
        """Pestaña de solicitud de acceso para nuevos usuarios."""
        frame = tk.Frame(self.notebook, bg="#1e1e2e", pady=10)
        self.notebook.add(frame, text="  Solicitar Acceso  ")

        info = "Nuevo usuario: rellena el formulario para recibir tus credenciales y certificado digital."
        tk.Label(
            frame, text=info, bg="#1e1e2e", fg="#aaaacc",
            font=("Helvetica", 8), justify="left", wraplength=440
        ).pack(anchor="w", padx=14, pady=(0, 8))

        fields = [
            ("reg_user_entry",  "Usuario (ej. jdoe):",              False),
            ("reg_pass_entry",  "Contraseña (mín. 8 caracteres):",  True),
            ("reg_pass2_entry", "Repite la contraseña:",            True),
            ("reg_role_entry",  "Rol (PDI, PAS, Estudiante…):",     False),
        ]
        for attr, label, secret in fields:
            tk.Label(frame, text=label, bg="#1e1e2e", fg="#aaaacc",
                     font=("Helvetica", 8)).pack(anchor="w", padx=14)
            entry = tk.Entry(
                frame, font=("Helvetica", 11), show="•" if secret else "",
                bg="#12121e", fg="#e0e0ff", insertbackground="white", relief=tk.FLAT
            )
            entry.pack(fill=tk.X, padx=14, pady=(1, 5), ipady=3)
            setattr(self, attr, entry)

        self.reg_btn = tk.Button(
            frame, text="📩  Solicitar Credenciales",
            font=("Helvetica", 10, "bold"), bg="#28a745", fg="white",
            relief=tk.FLAT, pady=7, activebackground="#219a38",
            activeforeground="white", command=self._on_register_click
        )
        self.reg_btn.pack(fill=tk.X, padx=14, pady=(4, 0))

        self.reg_status_var = tk.StringVar()
        self.reg_status_lbl = tk.Label(
            frame, textvariable=self.reg_status_var,
            bg="#1e1e2e", fg="#555577",
            font=("Helvetica", 8), wraplength=440, justify="left"
        )
        self.reg_status_lbl.pack(anchor="w", padx=14, pady=(5, 0))

    # ─────────────────────────────────────────────────────────────────────────
    #  Cola UI (thread-safe)
    # ─────────────────────────────────────────────────────────────────────────

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

    # ─────────────────────────────────────────────────────────────────────────
    #  Mensajes de chat y log
    # ─────────────────────────────────────────────────────────────────────────

    def _now(self) -> str:
        return datetime.now().strftime("%H:%M")

    def _chat_append(self, text: str, tag: str = "server", time_str: str = ""):
        """Añade una línea al área de chat con el tag de color indicado."""
        self.chat_area.config(state=tk.NORMAL)
        if time_str:
            self.chat_area.insert(tk.END, f"[{time_str}] ", "time")
        self.chat_area.insert(tk.END, text + "\n", tag)
        self.chat_area.see(tk.END)
        self.chat_area.config(state=tk.DISABLED)

    def chat_mine(self, msg: str):
        """Mensaje enviado por el usuario (azul, alineado a la derecha visualmente)."""
        self.run_ui(self._chat_append, f"  Tú ➤  {msg}", "mine", self._now())

    def chat_server(self, msg: str):
        """Respuesta del servidor (verde)."""
        self.run_ui(self._chat_append, f"  🖥  {msg}", "server", self._now())

    def chat_system(self, msg: str):
        """Mensaje de sistema/estado (gris pequeño)."""
        self.run_ui(self._chat_append, f"  ℹ  {msg}", "system")

    def chat_ok(self, msg: str):
        """Mensaje de éxito destacado (verde brillante)."""
        self.run_ui(self._chat_append, f"  ✅  {msg}", "ok")

    def chat_error(self, msg: str):
        """Mensaje de error (rojo)."""
        self.run_ui(self._chat_append, f"  ❌  {msg}", "error")

    # Log de sistema (pequeño, técnico)
    def log(self, message: str):
        self.run_ui(self._log, message)

    def _log(self, message: str):
        self.log_area.config(state=tk.NORMAL)
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)
        self.log_area.config(state=tk.DISABLED)

    # ─────────────────────────────────────────────────────────────────────────
    #  Lógica de auto-registro
    # ─────────────────────────────────────────────────────────────────────────

    def _on_register_click(self):
        username  = self.reg_user_entry.get().strip()
        password  = self.reg_pass_entry.get()
        password2 = self.reg_pass2_entry.get()
        role      = self.reg_role_entry.get().strip()

        if not username or not password or not role:
            messagebox.showerror("Campos vacíos", "Por favor, rellena todos los campos.")
            return
        if password != password2:
            messagebox.showerror("Contraseñas distintas", "Las dos contraseñas no coinciden.")
            return
        if len(password) < 8:
            messagebox.showerror("Contraseña muy corta",
                                 "La contraseña debe tener al menos 8 caracteres.")
            return

        self.reg_btn.config(state=tk.DISABLED, text="Enviando solicitud…")
        self._set_reg_status("⏳  Contactando con el servidor corporativo…", "#888899")
        self.log("[*] Iniciando solicitud de registro seguro (TLS 1.3)…")

        threading.Thread(
            target=self._register_thread,
            args=(username, password, role),
            daemon=True
        ).start()

    def _register_thread(self, username: str, password: str, role: str):
        """Hilo que envía la petición de registro al servidor (puerto 8444)."""
        sock = None
        try:
            ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3

            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(20)
            sock = ctx.wrap_socket(raw, server_hostname=HOST)
            sock.connect((HOST, REG_PORT))

            payload = json.dumps({
                "action":   "register",
                "username": username,
                "password": password,
                "role":     role,
            }).encode('utf-8')
            sock.sendall(payload)

            chunks = []
            while True:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                chunks.append(chunk)
            response_raw = b"".join(chunks).decode('utf-8')

        except ssl.SSLError as exc:
            self.run_ui(self._on_register_done, False,
                        f"Error de seguridad TLS: {exc}", None, None, username)
            return
        except Exception as exc:
            self.run_ui(self._on_register_done, False,
                        f"Error de red: {exc}", None, None, username)
            return
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

        try:
            resp = json.loads(response_raw)
        except json.JSONDecodeError:
            self.run_ui(self._on_register_done, False,
                        "Respuesta inválida del servidor.", None, None, username)
            return

        if resp.get("ok"):
            self.run_ui(self._on_register_done, True, None,
                        resp["cert"], resp["key"], username)
        else:
            self.run_ui(self._on_register_done, False,
                        resp.get("error", "Error desconocido."), None, None, username)

    def _on_register_done(self, success: bool, error_msg, cert_pem, key_pem, username):
        self.reg_btn.config(state=tk.NORMAL, text="📩  Solicitar Credenciales")

        if not success:
            self._set_reg_status(f"❌  {error_msg}", "#ff6b6b")
            self.log(f"[X] Registro fallido: {error_msg}")
            messagebox.showerror("Registro fallido", error_msg)
            return

        try:
            os.makedirs(CERTS_DIR, exist_ok=True)
            with open(os.path.join(CERTS_DIR, f"{username}-cert.pem"), 'w') as f:
                f.write(cert_pem)
            with open(os.path.join(CERTS_DIR, f"{username}-key.pem"), 'w') as f:
                f.write(key_pem)
        except OSError as exc:
            msg = f"No se pudieron guardar los certificados: {exc}"
            self._set_reg_status(f"❌  {msg}", "#ff6b6b")
            messagebox.showerror("Error guardando certificados", msg)
            return

        self._set_reg_status(
            f"✅  Usuario '{username}' registrado. Ya puedes iniciar sesión.", "#00cc66"
        )
        self.log(f"[OK] Certificado guardado en pki/certs/")

        self.user_entry.delete(0, tk.END)
        self.user_entry.insert(0, username)
        self.pass_entry.delete(0, tk.END)

        messagebox.showinfo(
            "Registro completado",
            f"¡Usuario '{username}' registrado con éxito!\n\n"
            "Tu certificado digital ha sido instalado.\n"
            "Ahora puedes iniciar sesión con tus credenciales."
        )
        self.notebook.select(0)

    def _set_reg_status(self, text: str, color: str = "#888899"):
        self.reg_status_var.set(text)
        self.reg_status_lbl.config(fg=color)

    # ─────────────────────────────────────────────────────────────────────────
    #  Lógica de conexión VPN
    # ─────────────────────────────────────────────────────────────────────────

    def connect_vpn(self):
        if self.connected:
            self.disconnect_vpn()
            return

        username = self.user_entry.get().strip()
        password = self.pass_entry.get()

        if not username or not password:
            messagebox.showerror("Error", "Por favor, introduce usuario y contraseña.")
            return

        client_cert = os.path.join(CERTS_DIR, f"{username}-cert.pem")
        client_key  = os.path.join(CERTS_DIR, f"{username}-key.pem")

        if not os.path.exists(client_cert) or not os.path.exists(client_key):
            resp = messagebox.askyesno(
                "Sin certificado",
                f"No se encuentran certificados mTLS para '{username}'.\n\n"
                "¿Deseas ir a «Solicitar Acceso» para registrarte?"
            )
            if resp:
                self.notebook.select(1)
                self.reg_user_entry.delete(0, tk.END)
                self.reg_user_entry.insert(0, username)
            return

        self.connect_btn.config(state=tk.DISABLED, text="Conectando…")
        self.log(f"[*] Iniciando Handshake mTLS (TLS 1.3) para '{username}'…")
        self.chat_system(f"Conectando al servidor VPN como '{username}'…")

        threading.Thread(
            target=self._connection_thread,
            args=(username, password, client_cert, client_key),
            daemon=True
        ).start()

    def _connection_thread(self, username, password, client_cert, client_key):
        sock = None
        try:
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.load_cert_chain(certfile=client_cert, keyfile=client_key)

            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(10)
            sock = context.wrap_socket(raw, server_hostname=HOST)
            sock.connect((HOST, PORT))

            cipher = sock.cipher()[0]
            self.log(f"[*] Cifrado: {cipher}")
            self.log(f"[*] Enviando credenciales para '{username}'…")

            sock.sendall(json.dumps({"username": username, "password": password}).encode('utf-8'))
            auth_response = sock.recv(1024).decode('utf-8', errors='replace')

            if auth_response.startswith("OK"):
                sock.settimeout(None)
                self.secure_sock = sock
                self.connected   = True
                self._username   = username
                self.log(f"[OK] Túnel VPN establecido. Cipher: {cipher}")
                self.run_ui(self._update_ui_connected, username)
                threading.Thread(
                    target=self._receive_thread, args=(sock,), daemon=True
                ).start()
            else:
                self.log(f"[X] Auth fallida: {auth_response.strip()}")
                self.run_ui(self.chat_error, f"Autenticación rechazada: {auth_response.strip()}")
                sock.close()
                self.run_ui(self._update_ui_disconnected)

        except ssl.SSLError as e:
            self.log(f"[X] Error mTLS: {e}")
            self.run_ui(self.chat_error, f"Error de seguridad mTLS: {e}")
            if sock:
                sock.close()
            self.run_ui(self._update_ui_disconnected)
        except Exception as e:
            self.log(f"[X] Error de red: {e}")
            self.run_ui(self.chat_error, f"Error de conexión: {e}")
            if sock:
                sock.close()
            self.run_ui(self._update_ui_disconnected)

    def _update_ui_connected(self, username: str = ""):
        self.connect_btn.config(
            state=tk.NORMAL, text="🔴  Cerrar Sesión", bg="#c0392b",
            activebackground="#a93226"
        )
        self.user_entry.config(state=tk.DISABLED)
        self.pass_entry.config(state=tk.DISABLED)

        # Activar campo de mensajes
        self.msg_entry.config(state=tk.NORMAL, bg="#12121e")
        self.msg_entry.delete(0, tk.END)
        self.msg_entry.focus_set()
        self.send_btn.config(state=tk.NORMAL, cursor="hand2")

        # Actualizar indicadores de estado
        self._status_lbl.config(text=f"● Conectado como {username}", fg="#00cc66")
        self._conn_badge.config(text=f"Sesión activa · {HOST}:{PORT}")

        self.chat_ok(f"Túnel VPN establecido con éxito · Usuario: {username}")
        self.chat_system("Escribe un mensaje abajo y pulsa Enviar o Enter.")

    def _update_ui_disconnected(self):
        self.connect_btn.config(
            state=tk.NORMAL, text="🔐  Iniciar Sesión Segura (mTLS)",
            bg="#004aad", activebackground="#0062d8"
        )
        self.user_entry.config(state=tk.NORMAL)
        self.pass_entry.config(state=tk.NORMAL)

        # Desactivar campo de mensajes
        self.msg_entry.config(state=tk.DISABLED, bg="#1e1e2e")
        self.msg_entry.delete(0, tk.END)
        self.msg_entry.insert(0, "Conéctate para poder enviar mensajes…")
        self.send_btn.config(state=tk.DISABLED, cursor="arrow")

        # Indicadores de estado
        self._status_lbl.config(text="● Desconectado", fg="#ff6b6b")
        self._conn_badge.config(text="Inicia sesión para chatear")
        self._username = ""

    def disconnect_vpn(self):
        sock = self.secure_sock
        if not sock:
            self._finish_disconnect()
            return
        self.chat_system("Cerrando sesión y desmontando el túnel VPN…")
        self.connect_btn.config(state=tk.DISABLED)
        try:
            sock.sendall(b"LOGOUT")
            self.after(3000, lambda: self._finish_disconnect(sock))
        except Exception:
            self._finish_disconnect(sock)

    def _finish_disconnect(self, expected=None):
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
        self.chat_system("Sesión cerrada.")

    def _receive_thread(self, sock):
        """Recibe mensajes del servidor y los muestra en el área de chat."""
        try:
            while self.secure_sock is sock:
                data = sock.recv(4096)
                if not data:
                    break
                text = data.decode('utf-8', errors='replace').strip()
                if text:
                    self.chat_server(text)
                    self.log(f"[SERVER] {text}")
        except Exception:
            pass
        finally:
            self.run_ui(self._finish_disconnect, sock)

    def on_close(self):
        sock = self.secure_sock
        if sock:
            try:
                sock.sendall(b"LOGOUT")
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass
        self.destroy()

    # ─────────────────────────────────────────────────────────────────────────
    #  Envío de mensajes
    # ─────────────────────────────────────────────────────────────────────────

    def send_message(self):
        if not self.connected:
            return
        msg = self.msg_entry.get().strip()
        if not msg:
            return

        self.msg_entry.delete(0, tk.END)
        self.chat_mine(msg)          # mostrar en azul a la derecha

        try:
            self.secure_sock.sendall(msg.encode('utf-8'))
        except Exception as e:
            self.chat_error(f"Error al enviar: {e}")
            self._finish_disconnect()


if __name__ == "__main__":
    app = VPNPortal()
    app.mainloop()
