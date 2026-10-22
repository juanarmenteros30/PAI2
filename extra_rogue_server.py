"""Servidor impostor para el extra de suplantación (+10%).

Presenta un certificado de servidor emitido por una CA distinta de la corporativa.
Un cliente que valide la cadena (como client.py) debe abortar el handshake con
CERTIFICATE_VERIFY_FAILED.  Uso:
    python extra_rogue_server.py
    python client/client.py -u pdi_user -p pdi_password123 --port 8445
"""
import os
import socket
import ssl
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'pki'))
from generate_pki import generate_ca, generate_cert

PORT = 8445


def make_context(tmpdir):
    ca_key, ca_cert = generate_ca(tmpdir)                       # CA falsa
    generate_cert(tmpdir, "server", ca_key, ca_cert, is_server=True)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(os.path.join(tmpdir, "server-cert.pem"), os.path.join(tmpdir, "server-key.pem"))
    return ctx


def main():
    with tempfile.TemporaryDirectory() as tmpdir:
        ctx = make_context(tmpdir)
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", PORT))
        srv.listen(5)
        print(f"[*] Servidor IMPOSTOR en 127.0.0.1:{PORT} (certificado de otra CA)")
        try:
            while True:
                c, addr = srv.accept()
                try:
                    ctx.wrap_socket(c, server_side=True).close()
                    print(f"[!] {addr} completó el handshake: el cliente NO validó la CA")
                except ssl.SSLError as e:
                    print(f"[+] {addr} abortó el handshake (suplantación detectada): {e}")
                    c.close()
        except KeyboardInterrupt:
            pass
        finally:
            srv.close()


if __name__ == '__main__':
    main()
