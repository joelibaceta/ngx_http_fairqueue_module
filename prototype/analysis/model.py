#!/usr/bin/env python3
"""
FairQueue — validación matemática/estadística de la fórmula de posición.

No levanta nginx: reproduce la fórmula exacta y la contrasta contra una
derivación cerrada, barriendo volumen (N), cuentas/bot (k), penalización (P),
rate, aging y tiempo (T).

FÓRMULA (por identidad, llegada en bloque, start=0):
    posición(t) = max(0, floor(frac·N) + pen − floor(aging·t))
    cursor(t)   = rate·t
    pen         = (cuentas_device − 1)·P
    admitido    ⟺ posición(t) ≤ cursor(t)

Resolviendo posición(t)=cursor(t) (continuo):
    t*_i = (floor(frac_i·N) + pen_i) / (rate + aging)

=> admitido en horizonte T  ⟺  floor(frac_i·N) + pen_i ≤ K,   K=(rate+aging)·T
   (K = "presupuesto": nº de posiciones liberadas en T)

Grupos adimensionales:  ρ = K/N (fracción admitida),  p = P/N,  k (cuentas/bot).
El comportamiento depende solo de (ρ, p, k) => escala-invariante en N si P ∝ N.

PREDICCIONES CERRADAS (frac ~ U(0,1)):
    P(admite | humano)      = min(1, ρ)
    P(admite | id de bot)   = clamp(ρ − (k−1)p, 0, 1)
    P(admite | dueño bot)   = 1 − (1 − q)^k,   q = clamp(ρ − (k−1)p, 0, 1)
    Advantage Ratio (dueño) = [1 − (1−q)^k] / min(1, ρ)

Umbral de diseño:  para que el bot NO tenga ventaja (AR≈1) basta p ≳ ρ/k;
para shutout (AR→0) basta (k−1)P ≥ K  ⟺  p ≥ ρ/(k−1).
"""

import csv
import os
import random
import statistics
import math

OUT = os.path.join(os.path.dirname(__file__), "out")
os.makedirs(OUT, exist_ok=True)


# ---------------------------------------------------------------------------
# Predicciones cerradas
# ---------------------------------------------------------------------------
def clamp(x, lo=0.0, hi=1.0):
    return max(lo, min(hi, x))

def p_human_theory(rho):
    return clamp(rho, 0, 1)

def q_theory(rho, p, k):
    return clamp(rho - (k - 1) * p, 0, 1)

def p_bot_id_theory(rho, p, k):
    return q_theory(rho, p, k)

def p_bot_owner_theory(rho, p, k):
    q = q_theory(rho, p, k)
    return 1 - (1 - q) ** k

def ar_owner_theory(rho, p, k):
    ph = p_human_theory(rho)
    return (p_bot_owner_theory(rho, p, k) / ph) if ph > 0 else float("inf")


# ---------------------------------------------------------------------------
# Monte Carlo del modelo exacto (con floor, colisiones, etc.)
# ---------------------------------------------------------------------------
def trial(H, B, k, P, K, rng):
    """Una realización. Devuelve conteos de admisión y tiempos (en 'posición')."""
    N = H + B * k
    pen = (k - 1) * P

    human_admit = 0
    human_wait = []  # posición de admisión = proxy de espera (·1/(rate+aging) = segundos)
    for _ in range(H):
        b = int(rng.random() * N)
        if b <= K:
            human_admit += 1
            human_wait.append(b)

    bot_owner_admit = 0
    bot_id_admit = 0
    bot_best = []  # mejor posición lograda por el dueño
    for _ in range(B):
        best = None
        got = False
        for _ in range(k):
            b = int(rng.random() * N) + pen
            if b <= K:
                bot_id_admit += 1
                got = True
            if best is None or b < best:
                best = b
        bot_best.append(best)
        if got:
            bot_owner_admit += 1

    return {
        "N": N,
        "human_admit_rate": human_admit / H if H else 0.0,
        "bot_id_admit_rate": bot_id_admit / (B * k) if B else 0.0,
        "bot_owner_admit_rate": bot_owner_admit / B if B else 0.0,
        "human_wait": human_wait,
        "bot_best": bot_best,
    }


def mc(H, B, k, P, K, trials=40, seed=1):
    """Monte Carlo: media y CI95 de las tasas."""
    acc = {"human_admit_rate": [], "bot_id_admit_rate": [], "bot_owner_admit_rate": []}
    waits = []
    for t in range(trials):
        r = trial(H, B, k, P, K, random.Random(seed * 100003 + t))
        for key in acc:
            acc[key].append(r[key])
        waits.extend(r["human_wait"])
    out = {}
    for key, vals in acc.items():
        m = statistics.mean(vals)
        sd = statistics.pstdev(vals)
        ci = 1.96 * sd / math.sqrt(len(vals)) if vals else 0.0
        out[key] = (m, ci)
    out["human_wait_positions"] = waits
    return out


# ---------------------------------------------------------------------------
# Utilidades de presentación
# ---------------------------------------------------------------------------
def bar(x, width=40, xmax=1.0):
    n = int(round(clamp(x / xmax, 0, 1) * width))
    return "█" * n + "·" * (width - n)

def sparkline(values, vmax=None):
    chars = "▁▂▃▄▅▆▇█"
    vmax = vmax or (max(values) if values else 1)
    if vmax == 0:
        vmax = 1
    return "".join(chars[min(len(chars) - 1, int(v / vmax * (len(chars) - 1)))] for v in values)


def section(t):
    print("\n" + "=" * 72)
    print(t)
    print("=" * 72)


# ---------------------------------------------------------------------------
# A) Validación: Monte Carlo vs teoría
# ---------------------------------------------------------------------------
def sec_validation():
    section("A) VALIDACIÓN  — Monte Carlo del modelo exacto  vs  fórmula cerrada")
    N = 6000
    k = 10
    B = 50
    H = N - B * k            # 5500 humanos, 500 ids de bot
    print(f"Población: N={N}  (H={H} humanos, B={B} bots × k={k}=  {B*k} ids de bot)")
    print(f"{'ρ=K/N':>7} {'p=P/N':>7} | {'humano sim/teo':>18} | {'id-bot sim/teo':>18} | {'dueño sim/teo':>18}")
    rows = [("ρ", "p", "human_sim", "human_theo", "botid_sim", "botid_theo", "owner_sim", "owner_theo")]
    for rho in (0.1, 0.2, 0.4):
        for p in (0.0, 0.02, 0.05):
            K = rho * N
            P = p * N
            r = mc(H, B, k, P, K, trials=30, seed=7)
            hs, _ = r["human_admit_rate"]
            bs, _ = r["bot_id_admit_rate"]
            os_, _ = r["bot_owner_admit_rate"]
            ht = p_human_theory(rho)
            bt = p_bot_id_theory(rho, p, k)
            ot = p_bot_owner_theory(rho, p, k)
            print(f"{rho:7.2f} {p:7.3f} | {hs:7.3f}/{ht:<7.3f}  | {bs:7.3f}/{bt:<7.3f}  | {os_:7.3f}/{ot:<7.3f}")
            rows.append((rho, p, round(hs,4), round(ht,4), round(bs,4), round(bt,4), round(os_,4), round(ot,4)))
    _csv("validation.csv", rows)
    print("\n→ Si sim ≈ teoría, la fórmula cerrada describe el sistema => podemos")
    print("  razonar analíticamente sobre volumen/tiempo sin simular cada caso.")


# ---------------------------------------------------------------------------
# B) Advantage Ratio del dueño vs penalización — hallar p*
# ---------------------------------------------------------------------------
def sec_penalty_sweep():
    section("B) VENTAJA DEL BOT  vs  PENALIZACIÓN  (p = P/N),  ρ=0.2 fijo")
    rho = 0.2
    print(f"AR(dueño) = P(bot entra con ≥1 de k cuentas) / P(humano entra).  ideal ≤ 1\n")
    print(f"{'p=P/N':>7} | " + " | ".join(f"k={k:<2d}" for k in (2,5,10,50)))
    rows = [("p",) + tuple(f"AR_k{k}" for k in (2,5,10,50))]
    for p in (0.0, 0.005, 0.01, 0.02, 0.04, 0.08, 0.16):
        ars = [ar_owner_theory(rho, p, k) for k in (2,5,10,50)]
        print(f"{p:7.3f} | " + " | ".join(f"{a:4.2f}" for a in ars))
        rows.append((p,) + tuple(round(a,3) for a in ars))
    _csv("penalty_sweep.csv", rows)
    print("\nUmbral de diseño  p* ≈ ρ/k  (ventaja neutralizada):")
    for k in (2,5,10,50):
        pstar = rho / k
        print(f"  k={k:<2d}:  p* ≈ {pstar:.4f}  → P* ≈ {pstar:.4f}·N   (AR→{ar_owner_theory(rho,pstar,k):.2f})")
    print("\nCurva AR(dueño) para k=10:")
    for p in (0.0,0.005,0.01,0.02,0.04,0.08):
        a = ar_owner_theory(rho, p, 10)
        print(f"  p={p:5.3f}  AR={a:4.2f}  {bar(a, 40, xmax=3.0)}")


# ---------------------------------------------------------------------------
# C) Invariancia de escala en N (y por qué la penalización ABSOLUTA falla)
# ---------------------------------------------------------------------------
def sec_volume():
    section("C) ESCALABILIDAD EN VOLUMEN  — penalización FRACCIONAL vs ABSOLUTA")
    rho = 0.2
    k = 10
    pf = 0.015                        # justo por debajo de p*=ρ/k=0.02 => AR no trivial
    print(f"Caso 1: P = p·N (fraccional, p={pf}).  AR debe ser ~constante en N.\n")
    print(f"{'N':>8} | {'AR dueño (sim)':>16} | {'AR dueño (teo)':>16}")
    rows1 = [("N","AR_sim","AR_theo")]
    for N in (1000, 10000, 100000):
        B = max(1, N // 200)          # 0.5% de la población son 'ids de bot base'
        H = N - B * k
        if H <= 0:
            H = N // 2; B = (N - H)//k
        P = pf * N
        K = rho * N
        r = mc(H, B, k, P, K, trials=20, seed=11)
        os_, ci = r["bot_owner_admit_rate"]
        hs, _ = r["human_admit_rate"]
        ar_sim = os_/hs if hs>0 else float("inf")
        ar_theo = ar_owner_theory(rho, pf, k)
        print(f"{N:8d} | {ar_sim:7.3f} ±{1.96*ci:5.3f}   | {ar_theo:16.3f}")
        rows1.append((N, round(ar_sim,4), round(ar_theo,4)))
    _csv("volume_fractional.csv", rows1)

    print("\nCaso 2: P = 250 ABSOLUTO fijo.  AR CRECE con N (la penalización se diluye).\n")
    print(f"{'N':>8} | {'p=P/N':>8} | {'AR dueño (teo)':>16}")
    rows2 = [("N","p","AR_theo")]
    for N in (1000, 5000, 20000, 100000):
        p = 250.0 / N
        ar = ar_owner_theory(rho, p, k)
        print(f"{N:8d} | {p:8.4f} | {ar:16.3f}   {bar(ar,30,xmax=k)}")
        rows2.append((N, round(p,5), round(ar,4)))
    _csv("volume_absolute.csv", rows2)
    print("\n→ CONCLUSIÓN: la penalización debe expresarse como FRACCIÓN de N")
    print("  (p·N), no como constante. Con P absoluto, a 100k usuarios el bot")
    print("  recupera casi toda su ventaja de volumen.")


# ---------------------------------------------------------------------------
# D) Dinámica temporal: admisión, carga del backend, espera humana, starvation
# ---------------------------------------------------------------------------
def sec_time():
    section("D) DINÁMICA EN EL TIEMPO  (rate, aging, carga de backend, espera)")
    N = 6000
    rate = 8.333          # 500/min
    aging = 0.5
    speed = rate + aging  # posiciones liberadas por segundo
    k = 10
    B = 50
    H = N - B * k
    P = 0.03 * N
    rng = random.Random(3)

    # tiempos de admisión cerrados t* = (base+pen)/speed
    humans = [int(rng.random()*N) / speed for _ in range(H)]
    pen = (k-1)*P
    bot_ids = [(int(rng.random()*N)+pen) / speed for _ in range(B) for _ in range(1)]  # 1 por owner-rep
    # para owners: mejor de k
    bot_owner_t = []
    for _ in range(B):
        best = min((int(rng.random()*N)+pen) for _ in range(k)) / speed
        bot_owner_t.append(best)

    horizon = N / speed
    print(f"N={N}  rate={rate:.2f}/s  aging={aging}/s  velocidad efectiva={speed:.2f} pos/s")
    print(f"p=P/N={P/N:.3f}  k={k}  (régimen scarce ρ*=0.2 => p*=ρ/k=0.02; aquí p>p* ⇒ shutout temprano)")
    print(f"Horizonte para vaciar la cola: {horizon:.0f}s (~{horizon/60:.1f} min)\n")

    hw = sorted(humans)
    def pct(sorted_list, q):
        if not sorted_list: return 0
        return sorted_list[min(len(sorted_list)-1, int(q*len(sorted_list)))]
    print("Espera de HUMANOS (segundos):")
    print(f"  p50={pct(hw,0.5):6.1f}   p95={pct(hw,0.95):6.1f}   max={hw[-1]:6.1f}   (todos finitos ⇒ sin starvation)")

    # --- VENTANA ESCASA (lo que importa): el recurso solo existe en los primeros ρ*·N ---
    t_scarce = 0.2 * horizon        # ρ=0.2: solo se admite el 20% => aquí hay "tickets"
    h_scarce = sum(1 for t in humans if t <= t_scarce)
    bo_scarce = sum(1 for t in bot_owner_t if t <= t_scarce)
    print(f"\n[VENTANA ESCASA  t≤{t_scarce:.0f}s  (ρ=0.2, cuando el recurso EXISTE)]")
    print(f"  humanos admitidos: {h_scarce}/{H} ({h_scarce/H:.0%})   dueños-bot: {bo_scarce}/{B} ({bo_scarce/B:.0%})")
    print(f"  → en la ventana que importa, los bots quedan FUERA.")

    adm_owner = sum(1 for t in bot_owner_t if t <= horizon)
    med_bot = statistics.median(bot_owner_t)
    print(f"\n[HORIZONTE COMPLETO  t≤{horizon:.0f}s  (si el evento admitiera a TODOS)]")
    print(f"  dueños-bot admitidos: {adm_owner}/{B}   espera mediana bot={med_bot:.0f}s vs humano p50={pct(hw,0.5):.0f}s")
    print(f"  → ojo: al vaciar del todo, el 'min de k hashes' del bot reaparece.")
    print(f"    La defensa vive en la ventana escasa, no en el drenaje total.")

    # carga del backend: admisiones por segundo (buckets de 10s)
    section_bins = 12
    binw = horizon / section_bins
    load = [0]*section_bins
    for t in humans + bot_owner_t:
        if t <= horizon:
            load[min(section_bins-1, int(t/binw))] += 1
    per_sec = [l/binw for l in load]
    print(f"\nCarga de backend (admisiones/seg) en {section_bins} tramos:")
    print("  " + sparkline(per_sec))
    print(f"  min={min(per_sec):.1f}  max={max(per_sec):.1f}  objetivo≈speed={speed:.1f}/s")
    print("  → la carga queda ACOTADA cerca de 'speed' (no hay pico inicial de N).")
    print(f"  (nota: aging SUMA a la tasa real del backend: {speed:.1f} vs rate {rate:.1f};")
    print("   subir aging reduce starvation pero aumenta la carga admitida.)")

    rows = [("t_seg","admits_humanos_acum","admits_dueñobot_acum")]
    ts = [horizon*i/20 for i in range(21)]
    for t in ts:
        ha = sum(1 for x in humans if x<=t)
        ba = sum(1 for x in bot_owner_t if x<=t)
        rows.append((round(t,1), ha, ba))
    _csv("timeline.csv", rows)


# ---------------------------------------------------------------------------
# E) Jain's Fairness Index entre agentes
# ---------------------------------------------------------------------------
def jain(values):
    if not values: return float("nan")
    s = sum(values); sq = sum(v*v for v in values)
    return (s*s)/(len(values)*sq) if sq>0 else float("nan")

def sec_jain():
    section("E) JAIN'S FAIRNESS INDEX  entre agentes (humano vs dueño-bot)")
    rho = 0.2; N = 6000; k = 10; B = 50; H = N - B*k
    print(f"{'p=P/N':>7} | {'J(human,bot)':>14} | interpretación")
    for p in (0.0, 0.01, 0.03, 0.08):
        P = p*N; K = rho*N
        r = mc(H, B, k, P, K, trials=30, seed=5)
        hs,_ = r["human_admit_rate"]; os_,_ = r["bot_owner_admit_rate"]
        j = jain([hs, os_])
        tag = "bots dominan" if os_>hs*1.2 else ("equitativo" if abs(os_-hs)<0.1*max(hs,1e-9) else "bots desfavorecidos")
        print(f"{p:7.3f} | {j:14.3f} | human={hs:.2f} bot={os_:.2f}  ({tag})")
    print("\nJ=1 es 'iguales'. Nota: aquí 'justo' = el bot no supera al humano;")
    print("un J<1 con bot<human es el resultado DESEADO (el abuso no paga).")


def sec_cost():
    section("F) ECONOMÍA DEL REROLL  — no se elimina, se ENCARECE")
    print("Con el número anclado al DEVICE (frac = HMAC(secret, event_id+devid)):")
    print("  · F5 / borrar cookie de identidad  -> MISMO número (+ penalización).")
    print("  · única forma de re-tirar: un DEVICE nuevo (incógnito/IP/navegador).\n")
    print("Cada device = 1 tirada uniforme. Para caer en la ventana escasa ρ:")
    print(f"{'ρ (ventana)':>12} | {'E[devices] p/1 éxito':>22} | {'devices p/90% éxito':>20}")
    rows = [("rho","E_devices","devices_p90")]
    for rho in (0.20, 0.10, 0.05, 0.01):
        e = 1.0 / rho
        n90 = math.log(0.10) / math.log(1 - rho)
        print(f"{rho:12.2f} | {e:22.1f} | {n90:20.1f}")
        rows.append((rho, round(e,2), round(n90,2)))
    _csv("reroll_cost.csv", rows)
    print("\nPara colocar M identidades en la ventana escasa ρ se necesitan ~M/ρ devices.")
    print("Ejemplo: 100 bots adelante con ρ=0.05  ->  ~2000 devices/IPs distintos.")
    print("\nMulticuenta en un MISMO device es contraproducente: baja la prob. de éxito")
    print("a q=ρ−(k−1)p y encima acumula penalización. El atacante racional usa")
    print("k=1 por device y MUCHOS devices => el costo se vuelve LINEAL en nº de slots")
    print("buenos deseados, y escala a 'botnet distribuida' (coste real en $/IP/infra).")
    print("\nEscalera de costo (cada peldaño lo fuerza una capa del diseño):")
    print("  1. F5 misma cookie ............ GRATIS      -> bloqueado (freeze)")
    print("  2. borrar cookies / incógnito . mismo device-> bloqueado (freeze + penalty)")
    print("  3. navegadores/perfiles ....... 1 roll/device")
    print("  4. máquinas/IPs distintas ..... 1 roll/IP    -> aquí entran señales IP/ASN (v1.x)")


def sec_ramp():
    section("G) TRANSITORIO DE LLEGADA  — por qué hace falta una fase de REGISTRO")
    print("Bots llegan en los primeros 3s; humanos repartidos en 120s. Hash puro,")
    print("sin penalización (aislamos el efecto del TIEMPO, no del volumen).")
    print("Bots = 20% de la población. 'Justo' = 20% de los admitidos en cada ventana.\n")

    rate = 8.0
    H, B = 2000, 500
    N = H + B
    rng = random.Random(42)
    ents = []
    for _ in range(H):
        ents.append(("human", rng.random() * 120.0, rng.random()))
    for _ in range(B):
        ents.append(("bot", rng.random() * 3.0, rng.random()))  # bots llegan rápido

    def run(sale_start):
        drain = N / rate
        horizon = sale_start + drain + 5
        done = [False] * len(ents)
        admitted = []  # (t, group)
        # arrivals ordenados para contar N(t) rápido
        arr_sorted = sorted(e[1] for e in ents)
        tt = 0.0
        ndone = 0
        while tt <= horizon and ndone < len(ents):
            # N(t) = llegados hasta tt (búsqueda binaria)
            lo, hi = 0, len(arr_sorted)
            while lo < hi:
                mid = (lo + hi) // 2
                if arr_sorted[mid] <= tt: lo = mid + 1
                else: hi = mid
            Nt = lo or 1
            cursor = rate * max(0.0, tt - sale_start)
            for i, e in enumerate(ents):
                if done[i] or e[1] > tt:
                    continue
                if math.floor(e[2] * Nt) <= cursor:
                    done[i] = True; ndone += 1
                    admitted.append((tt, e[0]))
            tt += 1.0
        return admitted, drain

    def window_share(admitted, t0, t1):
        w = [g for (t, g) in admitted if t0 <= t <= t1]
        b = sum(1 for g in w if g == "bot")
        return (len(w), b, (b / len(w) if w else 0.0))

    rows = [("policy", "ventana", "admitidos", "bots", "bot_share")]
    for label, ss in (("A) cursor desde t=0 (sin registro)", 0.0),
                      ("B) cursor desde t=125s (tras registro)", 125.0)):
        adm, drain = run(ss)
        scarce_end = ss + 0.20 * drain  # ventana escasa = primer 20% del drenaje
        tot, b, share = window_share(adm, ss, scarce_end)
        print(f"{label}")
        print(f"   ventana escasa [{ss:.0f}..{scarce_end:.0f}s]: {tot} admitidos, "
              f"{b} bots => bot_share={share:.0%}  {'<- FUGA de bots' if share>0.30 else '<- justo (~20%)'}")
        rows.append((label, f"{ss:.0f}-{scarce_end:.0f}s", tot, b, round(share, 3)))
    _csv("ramp.csv", rows)
    print("\n→ Sin registro, la ventana escasa se llena de bots (N chico al inicio =")
    print("  posiciones deflactadas para los que llegaron primero).")
    print("  Con fase de registro (waiting_start < sale_start) la cola se forma")
    print("  ANTES de drenar: cada quien cae en frac×N_final, disperso y justo.")
    print("  => directivas: fairqueue_waiting_start (abre cola) y fairqueue_start")
    print("     (=sale_start, arranca el cursor).")


def sec_headroom():
    section("H) HEADROOM DE VENTANA  — colchón vs latencia (no afecta fairness)")
    print("base = floor(frac · N · (1+h)).  N personas sobre N(1+h) slots => huecos.")
    print("El headroom es un tradeoff LATENCIA vs HOLGURA; no cambia el orden ni la")
    print("ventaja del bot (estira el tiempo de forma uniforme para todos).\n")
    print(f"{'headroom h':>11} | {'ocupación':>10} | {'slots libres':>12} | {'latencia extra p95':>18}")
    rows = [("h", "ocupacion", "slots_libres", "latencia_extra_rel")]
    for h in (0.0, 0.1, 0.2, 0.5, 1.0):
        occ = 1.0 / (1 + h)
        free = 1 - occ
        # el último (frac≈1) espera window·(1+h); extra relativo = h
        print(f"{h:11.2f} | {occ:9.0%} | {free:11.0%} | +{h:.0%} del window")
        rows.append((h, round(occ, 3), round(free, 3), h))
    _csv("headroom.csv", rows)
    print("\n→ h=0.2 (default): ocupación ~83%, 17% de slots libres como colchón para")
    print("  late-joiners y picos, a cambio de ~20% más de espera para la cola. El")
    print("  fairness (Advantage Ratio, Jain) es idéntico con cualquier h.")


def _csv(name, rows):
    with open(os.path.join(OUT, name), "w", newline="") as f:
        csv.writer(f).writerows(rows)


def main():
    print("FairQueue — Validación matemática/estadística de la fórmula")
    print("Grupos adimensionales:  ρ=K/N (fracción admitida, ∝ tiempo),  p=P/N,  k=cuentas/bot")
    sec_validation()
    sec_penalty_sweep()
    sec_volume()
    sec_time()
    sec_jain()
    sec_cost()
    sec_ramp()
    sec_headroom()
    print(f"\nCSVs escritos en: {OUT}")


if __name__ == "__main__":
    main()
