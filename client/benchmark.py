import argparse
import json
import os
import socket
import ssl
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from bench_common import run_benchmark, USERS, MSGS_PER_CLIENT

HOST = 'localhost'
PORT = 8443
CERTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'pki', 'certs')
CA_CERT = os.path.join(CERTS_DIR, 'ca-cert.pem')


def vpn_client_worker(i):
    user, pwd = USERS[i % len(USERS)]
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(os.path.join(CERTS_DIR, f"{user}-cert.pem"),
                        os.path.join(CERTS_DIR, f"{user}-key.pem"))
    t0 = time.perf_counter()
    s = ctx.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=HOST)
    s.connect((HOST, PORT))                       # incluye el handshake mTLS TLS 1.3
    t_hs = time.perf_counter() - t0

    t1 = time.perf_counter()
    s.sendall(json.dumps({"username": user, "password": pwd}).encode())
    if b"OK" not in s.recv(1024):
        raise RuntimeError("login rechazado")
    t_login = time.perf_counter() - t1

    rtts = []
    for _ in range(MSGS_PER_CLIENT):
        t = time.perf_counter()
        s.sendall(b"BENCHMARK_DATA\n")
        s.recv(1024)
        rtts.append(time.perf_counter() - t)
        time.sleep(0.1)                           # mantiene las sesiones solapadas
    s.sendall(b"LOGOUT")
    s.recv(1024)
    try:
        s.unwrap()
    except Exception:
        pass
    s.close()
    return t_hs, t_login, statistics.mean(rtts)


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument("--clients", type=int, default=300)
    ap.add_argument("--ramp", type=float, default=0.0, help="segundos en los que escalonar el inicio de los clientes")
    ap.add_argument("--pid", type=int, help="PID del servidor (mide CPU/RAM si hay psutil)")
    a = ap.parse_args()
    run_benchmark(vpn_client_worker, a.clients, "VPN TLS 1.3 + mTLS", "benchmark_tls.csv", a.pid, a.ramp)
