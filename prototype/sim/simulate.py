#!/usr/bin/env python3
"""
FairQueue — simulador humanos vs bots (solo stdlib).

Mide si la cola cumple su objetivo: que la ventaja de los bots (velocidad +
volumen) desaparezca, sin bloquearlos y sin castigar a los humanos.

Modelo de cada agente:
  - humano:  1 identidad, 1 device, polling tranquilo.
  - bot:     N identidades compartiendo el MISMO device (multi-cuenta/retry),
             polling agresivo. Se queda con su MEJOR identidad.

El simulador habla con el prototipo OpenResty por HTTP. Cada "identidad" es un
jar de cookies independiente; un device compartido = reutilizar la cookie fq_dev.

Uso:
    python3 simulate.py --humans 200 --bots 20 --accounts-per-bot 10 --duration 60

Métricas clave:
  - Bot Advantage Ratio = P(admitido|bot-identity) / P(admitido|humano).
    Ideal <= 1  (ser bot no da ventaja).
  - Posición mediana inicial de humanos vs identidades-bot.
  - Jain's Fairness Index sobre tasa de éxito por grupo.
"""

import argparse
import http.cookiejar
import json
import random
import statistics
import threading
import time
import urllib.error
import urllib.request

LOCK = threading.Lock()


def rand_ip():
    return "10.%d.%d.%d" % (random.randint(1, 254), random.randint(0, 255), random.randint(1, 254))


class Client:
    """Una 'identidad': su propio jar de cookies, device opcional compartido, y
    una IP simulada vía X-Forwarded-For (el edge corre con trust_xff en la demo)."""

    def __init__(self, base, shared_dev=None, xff=None):
        self.base = base.rstrip("/")
        self.xff = xff or rand_ip()
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar),
            NoRedirect(),
        )
        if shared_dev:
            self._inject_cookie("fq_dev", shared_dev)

    def _inject_cookie(self, name, value):
        host = self.base.split("://", 1)[1].split("/", 1)[0].split(":")[0]
        c = http.cookiejar.Cookie(
            version=0, name=name, value=value, port=None, port_specified=False,
            domain=host, domain_specified=True, domain_initial_dot=False,
            path="/", path_specified=True, secure=False, expires=None,
            discard=False, comment=None, comment_url=None, rest={},
        )
        self.jar.set_cookie(c)

    def device_cookie(self):
        for c in self.jar:
            if c.name == "fq_dev":
                return c.value
        return None

    def status(self):
        req = urllib.request.Request(self.base + "/__fairqueue/status")
        req.add_header("X-Forwarded-For", self.xff)
        with self.opener.open(req, timeout=10) as r:
            return json.loads(r.read().decode())

    def prime(self):
        """Primer contacto: fija cookies de identidad/device."""
        try:
            self.status()
        except Exception:
            pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def human(base, duration, results):
    c = Client(base)
    c.prime()
    first_pos, admitted_at = None, None
    deadline = time.time() + duration
    while time.time() < deadline:
        try:
            d = c.status()
        except Exception:
            time.sleep(2.0)
            continue
        if d.get("state") == "admitted":
            admitted_at = time.time()
            break
        if first_pos is None:
            first_pos = d.get("position")
        time.sleep(2.0)  # polling humano tranquilo
    with LOCK:
        results["human"].append({"first_pos": first_pos, "admitted": admitted_at is not None})


def bot(base, accounts, duration, results):
    """Un bot con N identidades compartiendo device; se queda con la mejor."""
    dev = Client(base)
    dev.prime()
    shared_dev = dev.device_cookie()  # mismo device para todas sus cuentas
    # Misma máquina => misma IP para todas las cuentas.
    identities = [dev] + [Client(base, shared_dev=shared_dev, xff=dev.xff)
                          for _ in range(accounts - 1)]
    for c in identities:
        c.prime()

    best_first = None
    admitted = False
    deadline = time.time() + duration
    while time.time() < deadline and not admitted:
        for c in identities:
            try:
                d = c.status()
            except Exception:
                continue
            if d.get("state") == "admitted":
                admitted = True
                break
            p = d.get("position")
            if p is not None and (best_first is None or p < best_first):
                best_first = p
        time.sleep(0.2)  # polling agresivo
    with LOCK:
        results["bot"].append({"first_pos": best_first, "admitted": admitted, "accounts": accounts})


def distributed_bot(base, devices, duration, results):
    """Bot DISTRIBUIDO: devices distintos (sin cookie compartida). Cada device es
    una tirada de hash independiente => recupera el 'mejor de D'. Modela al
    atacante que paga D navegadores/IPs. Mide ventaja vs costo (devices)."""
    # Versión BARATA: muchos devices pero UNA sola IP (una máquina con muchas
    # cookies). El cap/penalización por IP debería atraparlo ahora.
    ipx = rand_ip()
    ids = [Client(base, xff=ipx) for _ in range(devices)]
    for c in ids:
        c.prime()
    best, admitted = None, False
    deadline = time.time() + duration
    while time.time() < deadline and not admitted:
        for c in ids:
            try:
                d = c.status()
            except Exception:
                continue
            if d.get("state") == "admitted":
                admitted = True; break
            p = d.get("position")
            if p is not None and (best is None or p < best):
                best = p
        time.sleep(0.2)
    with LOCK:
        results["dist"].append({"first_pos": best, "admitted": admitted, "devices": devices})


def jain(values):
    if not values:
        return float("nan")
    s = sum(values)
    sq = sum(v * v for v in values)
    n = len(values)
    return (s * s) / (n * sq) if sq > 0 else float("nan")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://localhost:8080")
    ap.add_argument("--humans", type=int, default=200)
    ap.add_argument("--bots", type=int, default=20)
    ap.add_argument("--accounts-per-bot", type=int, default=10)
    ap.add_argument("--dist-bots", type=int, default=10)
    ap.add_argument("--devices-per-dist-bot", type=int, default=10)
    ap.add_argument("--duration", type=int, default=60)
    args = ap.parse_args()

    results = {"human": [], "bot": [], "dist": []}
    threads = []

    print(f"Lanzando {args.humans} humanos, {args.bots} bots multicuenta "
          f"({args.accounts_per_bot} cuentas/mismo device) y {args.dist_bots} bots "
          f"distribuidos ({args.devices_per_dist_bot} devices c/u) por {args.duration}s\n")

    for _ in range(args.humans):
        t = threading.Thread(target=human, args=(args.base, args.duration, results))
        t.start(); threads.append(t)
    for _ in range(args.bots):
        t = threading.Thread(target=bot, args=(args.base, args.accounts_per_bot, args.duration, results))
        t.start(); threads.append(t)
    for _ in range(args.dist_bots):
        t = threading.Thread(target=distributed_bot,
                             args=(args.base, args.devices_per_dist_bot, args.duration, results))
        t.start(); threads.append(t)
    for t in threads:
        t.join()

    def med(v):
        return round(statistics.median(v)) if v else None

    hs = results["human"]
    h_adm = sum(1 for x in hs if x["admitted"])
    h_rate = h_adm / len(hs) if hs else 0
    h_pos = [x["first_pos"] for x in hs if x["first_pos"] is not None]

    # bot multicuenta (mismo device): con frac anclado al device sus N cuentas
    # comparten número => sin ventaja; se mide por DUEÑO.
    bs = results["bot"]
    b_own = sum(1 for x in bs if x["admitted"]) / len(bs) if bs else 0
    b_pos = [x["first_pos"] for x in bs if x["first_pos"] is not None]

    # bot distribuido (devices distintos): mejor-de-D, cuesta D devices.
    ds = results["dist"]
    d_own = sum(1 for x in ds if x["admitted"]) / len(ds) if ds else 0
    d_pos = [x["first_pos"] for x in ds if x["first_pos"] is not None]
    dev_used = sum(x["devices"] for x in ds)

    print("==================== RESULTADOS ====================")
    print(f"{'grupo':<22}{'éxito':>8}{'pos.ini med':>13}{'AdvRatio':>10}")
    print(f"{'humano (1 device)':<22}{h_rate:>8.2f}{str(med(h_pos)):>13}{1.00:>10.2f}")
    if bs:
        print(f"{'bot multicuenta':<22}{b_own:>8.2f}{str(med(b_pos)):>13}"
              f"{(b_own/h_rate if h_rate else 0):>10.2f}")
    if ds:
        print(f"{'bot distribuido':<22}{d_own:>8.2f}{str(med(d_pos)):>13}"
              f"{(d_own/h_rate if h_rate else 0):>10.2f}")
    print("====================================================")
    print(f"Jain (humano, multicuenta, distribuido): {jain([h_rate, b_own, d_own]):.3f}")
    if ds:
        print(f"\nBot distribuido: usó {dev_used} devices para {args.dist_bots} bots "
              f"({args.devices_per_dist_bot} c/u). Su ventaja CUESTA devices/IPs reales:")
        print(f"  éxito por device = {d_own*args.dist_bots/max(dev_used,1):.3f} "
              f"(vs humano {h_rate:.3f}).")
    print("\nLectura: el bot multicuenta (mismo device) NO gana — con frac anclado al")
    print("device sus cuentas comparten número. El distribuido sí recupera ventaja,")
    print("pero linealmente en devices/IPs: eso es el COSTO económico, no un bloqueo.")


if __name__ == "__main__":
    main()
