import argparse
import json
import os
import socket
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from bench_common import run_benchmark, USERS, MSGS_PER_CLIENT

HOST = 'localhost'
PORT = 8080


def plaintext_client_worker(i):
    user, pwd = USERS[i % len(USERS)]
    t0 = time.perf_counter()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    t_hs = time.perf_counter() - t0               # solo el handshake TCP

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
        time.sleep(0.1)
    s.sendall(b"LOGOUT")
    s.recv(1024)
    s.close()
    return t_hs, t_login, statistics.mean(rtts)


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument("--clients", type=int, default=300)
    ap.add_argument("--ramp", type=float, default=0.0, help="segundos en los que escalonar el inicio de los clientes")
    ap.add_argument("--pid", type=int, help="PID del servidor (mide CPU/RAM si hay psutil)")
    a = ap.parse_args()
    run_benchmark(plaintext_client_worker, a.clients, "SIN CIFRAR (plaintext)", "benchmark_plaintext.csv", a.pid, a.ramp)
