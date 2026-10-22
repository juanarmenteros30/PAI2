"""Utilidades comunes de benchmark: estadísticas, CSV y muestreo de CPU/RAM del servidor."""
import csv
import statistics
import threading
import time

try:
    import psutil
except ImportError:          # psutil es opcional
    psutil = None

MSGS_PER_CLIENT = 20
USERS = [("pdi_user", "pdi_password123"),
         ("pas_user", "pas_password123"),
         ("inv_user", "inv_password123")]


def _pct(values, q):
    if len(values) < 2:
        return values[0] if values else float('nan')
    return statistics.quantiles(values, n=100)[q - 1]


def run_benchmark(worker, num_clients, label, csv_path, server_pid=None, ramp=0.0):
    """worker(i) -> (t_handshake, t_login, rtt_medio) o lanza excepción."""
    results, failed = [], [0]
    lock = threading.Lock()

    def wrapped(i):
        if ramp:
            time.sleep(i * ramp / num_clients)     # escalona el inicio de los clientes
        try:
            r = worker(i)
            with lock:
                results.append(r)
        except Exception:
            with lock:
                failed[0] += 1

    samples, stop = [], threading.Event()
    proc = psutil.Process(server_pid) if (psutil and server_pid) else None

    def sampler():
        proc.cpu_percent(None)
        while not stop.is_set():
            time.sleep(0.5)
            samples.append((proc.cpu_percent(None), proc.memory_info().rss / 1e6))

    if proc:
        threading.Thread(target=sampler, daemon=True).start()

    print(f"[*] Benchmark {label}: {num_clients} clientes concurrentes...")
    t0 = time.perf_counter()
    threads = [threading.Thread(target=wrapped, args=(i,)) for i in range(num_clients)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    total = time.perf_counter() - t0
    stop.set()

    print(f"\n--- RESULTADOS ({label}) ---")
    print(f"Exitosas: {len(results)}  Fallidas: {failed[0]}  Tiempo total: {total:.2f} s")
    if results:
        for idx, name in enumerate(("Handshake/conexión", "Login", "RTT mensaje")):
            col = [r[idx] * 1000 for r in results]
            print(f"{name:20s} media {statistics.mean(col):8.2f} ms | "
                  f"p50 {_pct(col, 50):8.2f} | p95 {_pct(col, 95):8.2f} | máx {max(col):8.2f}")
        print(f"Throughput: {len(results) * MSGS_PER_CLIENT / total:.1f} mensajes/s")
    if samples:
        print(f"Servidor: CPU máx {max(s[0] for s in samples):.0f}% | RAM máx {max(s[1] for s in samples):.1f} MB")
    with open(csv_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["handshake_s", "login_s", "rtt_medio_s"])
        w.writerows(results)
    print(f"[*] Detalle guardado en {csv_path}")
