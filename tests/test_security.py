"""Pruebas de seguridad de PAI-2 (arrancan el servidor real como subproceso).

    python -m unittest discover -s tests -v
"""
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
CERTS = os.path.join(ROOT, 'pki', 'certs')
AUDIT = os.path.join(ROOT, 'server', 'audit.log')
HOST, PORT = 'localhost', 8443
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, 'pki'))


def make_ctx(cert=None, cafile=None, tls12=False):
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cafile or os.path.join(CERTS, 'ca-cert.pem'))
    if tls12:
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    else:
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    if cert:
        ctx.load_cert_chain(os.path.join(CERTS, f'{cert}-cert.pem'), os.path.join(CERTS, f'{cert}-key.pem'))
    return ctx


def connect(cert=None, **kw):
    s = make_ctx(cert, **kw).wrap_socket(socket.socket(), server_hostname=HOST)
    s.settimeout(5)
    s.connect((HOST, PORT))
    return s


def login(cert, user, pwd):
    s = connect(cert)
    try:
        s.sendall(json.dumps({"username": user, "password": pwd}).encode())
        return s.recv(200).decode()
    finally:
        s.close()


def audit_text():
    try:
        with open(AUDIT, encoding='utf-8', errors='replace') as f:
            return f.read()
    except FileNotFoundError:
        return ''


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Si ya hay algo escuchando en 8443 (p. ej. un servidor viejo), los resultados no serían fiables
        try:
            socket.create_connection(('127.0.0.1', PORT), timeout=0.5).close()
        except OSError:
            pass
        else:
            raise RuntimeError("Ya hay un proceso escuchando en el puerto 8443. "
                               "Cierra el servidor que tengas abierto y repite.")
        cls.audit_start = len(audit_text())
        cls.out = tempfile.TemporaryFile()
        env = dict(os.environ, PYTHONUTF8='1', PYTHONIOENCODING='utf-8')
        cls.proc = subprocess.Popen([sys.executable, os.path.join(ROOT, 'server', 'server.py')],
                                    stdout=cls.out, stderr=subprocess.STDOUT, env=env, cwd=ROOT)
        deadline = time.time() + 15
        while time.time() < deadline:
            if cls.proc.poll() is not None:
                raise RuntimeError(f"El servidor terminó al arrancar (código {cls.proc.returncode}):\n{cls._server_output()}")
            try:
                socket.create_connection(('127.0.0.1', PORT), timeout=0.5).close()
                return
            except OSError:
                time.sleep(0.2)
        cls.proc.terminate()
        raise RuntimeError(f"El servidor no escucha tras 15 s. Salida:\n{cls._server_output()}")

    @classmethod
    def _server_output(cls):
        cls.out.seek(0)
        return cls.out.read().decode('utf-8', errors='replace')

    def audit_new(self):
        """Texto del audit log escrito desde que arrancó este servidor."""
        return audit_text()[self.audit_start:]

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, 'proc', None) and cls.proc.poll() is None:
            cls.proc.terminate()
            cls.proc.wait(5)
        if getattr(cls, 'out', None):
            cls.out.close()

    def test_01_login_legitimo_tls13_aead(self):
        s = connect('pdi_user')
        self.assertEqual(s.version(), 'TLSv1.3')
        self.assertIn(s.cipher()[0], {'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256'})
        s.sendall(json.dumps({"username": "pdi_user", "password": "pdi_password123"}).encode())
        self.assertTrue(s.recv(200).startswith(b'OK'))
        s.sendall(b'LOGOUT')
        self.assertIn(b'Sesion cerrada', s.recv(200))
        s.close()

    def test_02_password_incorrecta(self):
        self.assertTrue(login('pas_user', 'pas_user', 'mala').startswith('ERROR'))

    def test_03_certificado_de_otro_usuario_es_suplantacion(self):
        self.assertTrue(login('pas_user', 'pdi_user', 'pdi_password123').startswith('ERROR'))
        time.sleep(0.2)
        self.assertIn("SUPLANTACIÓN: cert CN='pas_user' intenta entrar como 'pdi_user'", self.audit_new())

    def test_04_cliente_sin_certificado_rechazado_y_auditado(self):
        s = None
        try:
            with self.assertRaises((ssl.SSLError, ConnectionError, OSError)):
                s = connect(None)
                s.sendall(b'{}')
                if not s.recv(10):
                    raise ConnectionError("cerrado")
        finally:
            if s:
                s.close()
        time.sleep(0.3)
        self.assertIn('Handshake mTLS RECHAZADO', self.audit_new())

    def test_05_tls12_rechazado(self):
        s = make_ctx('pdi_user', tls12=True).wrap_socket(socket.socket(), server_hostname=HOST)
        s.settimeout(5)
        try:
            with self.assertRaises((ssl.SSLError, OSError)):
                s.connect((HOST, PORT))
        finally:
            s.close()

    def test_06_cliente_colgado_no_bloquea_el_servidor(self):
        idle = socket.create_connection((HOST, PORT))          # TCP sin handshake
        try:
            t = time.time()
            self.assertTrue(login('inv_user', 'inv_user', 'inv_password123').startswith('OK'))
            self.assertLess(time.time() - t, 2)
        finally:
            idle.close()

    def test_07_servidor_impostor_con_otra_ca_es_rechazado_por_el_cliente(self):
        from extra_rogue_server import make_context as rogue_ctx
        with tempfile.TemporaryDirectory() as d:
            ctx = rogue_ctx(d)
            srv = socket.socket()
            srv.bind(('127.0.0.1', 0))
            srv.listen(1)
            port = srv.getsockname()[1]

            def serve():
                c, _ = srv.accept()
                try:
                    ctx.wrap_socket(c, server_side=True)
                except ssl.SSLError:
                    pass
            threading.Thread(target=serve, daemon=True).start()
            cli = make_ctx('pdi_user').wrap_socket(socket.socket(), server_hostname=HOST)
            cli.settimeout(5)
            try:
                with self.assertRaises(ssl.SSLCertVerificationError):
                    cli.connect(('127.0.0.1', port))
            finally:
                cli.close()
                srv.close()

    def test_99_bloqueo_tras_intentos_fallidos(self):   # último: bloquea a inv_user durante 60 s
        for _ in range(5):
            login('inv_user', 'inv_user', 'mala')
        self.assertIn('bloqueada', login('inv_user', 'inv_user', 'inv_password123'))
        time.sleep(0.2)
        self.assertIn('cuenta bloqueada', self.audit_new().lower())


class DbTests(unittest.TestCase):
    def test_hash_no_reversible_y_verificacion(self):
        sys.path.insert(0, os.path.join(ROOT, 'server'))
        import sqlite3
        import db
        with sqlite3.connect(db.DB_PATH) as c:
            salt, h = c.execute("SELECT salt, password_hmac FROM users WHERE username='pdi_user'").fetchone()
        self.assertNotIn('pdi_password123', h)
        self.assertEqual(len(bytes.fromhex(salt)), 32)
        self.assertIsNotNone(db.verify_user('pdi_user', 'pdi_password123'))
        self.assertIsNone(db.verify_user('pdi_user', 'otra'))
        self.assertIsNone(db.verify_user("x' OR '1'='1", 'x'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
