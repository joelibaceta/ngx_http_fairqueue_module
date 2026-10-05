# Genera docs/assignment-comparison.gif: una población que llega en el tiempo,
# repartida por tres reglas de admisión (FIFO, Random por lotes, Hash con ventana).
# Demostrativo: ilustra cómo un lote tardío de personas termina al fondo con
# FIFO/Random y disperso (incluso al frente) con Hash.
#
#   pip install numpy matplotlib pillow
#   python notebook/make_animation.py
import os
import matplotlib
matplotlib.use("Agg")
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation, PillowWriter
from matplotlib.lines import Line2D

OUT = os.path.join(os.path.dirname(__file__), "..", "docs", "assignment-comparison.gif")
rng = np.random.default_rng(3)
N = 200
red_frac = 0.14
h = 0.3
S = int(round(N * (1 + h)))     # slots de la grilla (abajo), con headroom -> huecos
COLS = 20
GROWS = int(np.ceil(S / COLS))
WROWS = 7                        # alto de la sala de espera (el pico en espera ~110)
DUR = 5.0                        # duración total (segundos)
BOTS_UNTIL = 1.5                 # los bots terminan de llegar aquí; luego solo humanos
# Identidades: minoría humana. Bots al inicio del índice, humanos al final.
n_red = 30
is_human = np.zeros(N, bool); is_human[N - n_red:] = True

# Llegadas (s). Bots en ráfaga 0..1.5. Humanos: unos pocos temprano y una RÁFAGA
# tardía (3.3..3.8) que se ACUMULA en la sala, para ver cómo la reparte cada regla.
arr = np.empty(N)
arr[~is_human] = rng.uniform(0.0, BOTS_UNTIL, N - n_red)
hidx = np.where(is_human)[0]
n_early = 12
arr[hidx[:n_early]] = rng.uniform(0.8, 2.5, n_early)           # humanos tempranos, dispersos
arr[hidx[n_early:]] = rng.uniform(3.3, 3.8, n_red - n_early)   # ráfaga tardía (se acumula)
order = np.argsort(arr)
rank = np.empty(N, int); rank[order] = np.arange(N)

# Admisión medida por ritmo: el cursor recorre la ventana de cada regla (N para
# fifo, S para hash) y termina ~t=DUR; como es más lenta que las llegadas, se
# forma cola. Una llegada tardía cae apenas el cursor ya pasó su slot.
def drop_of(pos, window):
    return np.maximum(arr, pos * DUR / window)

# FIFO: slot = orden de llegada -> los últimos (humanos tardíos) van al fondo.
fifo_pos = rank.copy()
fifo_drop = drop_of(fifo_pos, N)

# HASH: slot fijo por hash sobre la ventana con huecos. Para comparar el MISMO
# batch rojo, el grueso (bots + humanos tempranos) termina de drenar ~3.2 s; la
# ráfaga roja se acumula y cae junta ~4.3 s, cada uno a su hueco (disperso).
hash_pos = rng.permutation(S)[:N]
burst = hidx[n_early:]
nonburst = np.setdiff1d(np.arange(N), burst)

# Demostrativo: que VARIAS del batch rojo caigan en huecos de las primeras filas.
# Elegimos slots al frente y se los asignamos a parte del batch, intercambiando
# con quien los tuviera (así se mantienen únicos). El resto del batch queda
# disperso por su hash natural (medio/fondo).
front_targets = np.array([2, 7, 13, 21, 24, 33, 38, 45])     # slots en las primeras filas
n_front = min(len(front_targets), len(burst) // 2)
movers = burst[:n_front]
for m, tgt in zip(movers, front_targets[:n_front]):
    cur_m = hash_pos[m]
    owner = np.where(hash_pos == tgt)[0]
    if owner.size:                       # quien tenía el slot front se queda con el de m
        hash_pos[owner[0]] = cur_m
    hash_pos[m] = tgt
hash_drop = np.empty(N)
hash_drop[nonburst] = np.maximum(arr[nonburst], hash_pos[nonburst] * 3.2 / S)
hash_drop[burst] = rng.uniform(4.2, 4.6, len(burst))

# RANDOM: por lotes. En cada ola se toma la fila, se BARAJA y se asigna al
# siguiente bloque. El hueco tras t=3.0 deja que la ráfaga humana se acumule
# hasta la ola de 4.5, y como es casi pura humana, barajar no cambia nada: al fondo.
wave_times = np.array([0.6, 1.4, 2.2, 3.0, 4.5, 4.95])
rand_pos = np.full(N, -1, int)
rand_drop = np.full(N, DUR, float)
rand_wave = np.full(N, -1, int)
cur = 0
for w, wt in enumerate(wave_times):
    cand = np.where((arr <= wt) & (rand_pos < 0))[0]
    if len(cand) == 0:
        continue
    cand = cand[rng.permutation(len(cand))]          # barajar la fila
    rand_pos[cand] = np.arange(cur, cur + len(cand))
    rand_drop[cand] = wt
    rand_wave[cand] = w
    cur += len(cand)
leftover = np.where(rand_pos < 0)[0]
rand_pos[leftover] = np.arange(cur, cur + len(leftover))
rand_drop[leftover] = np.maximum(arr[leftover], wave_times[-1])
rand_wave[leftover] = len(wave_times)

strategies = [
    ("FIFO\narrival order",        fifo_pos, fifo_drop, "fifo"),
    ("Random\nshuffle, then fill",  rand_pos, rand_drop, "rand"),
    ("Hash\nwindowed, with gaps",  hash_pos, hash_drop, "hash"),
]

BLUE = "#4169e1"; RED = "#dc143c"
FLY = 0.12
FPS = 14
HOLD = 10                        # frames de pausa al final antes del loop
ts = list(np.linspace(0.0, DUR + 0.2, 150)) + [DUR + 0.2] * HOLD

def grid_xy(pos):
    pos = np.asarray(pos); return pos % COLS, -1.0 - pos // COLS

def pile_xy(k):
    return k % COLS, 1.0 + k // COLS

fig, axes = plt.subplots(1, 3, figsize=(12, 5.6), dpi=80)
S_seat, S_wait, S_fly = [], [], []
for ax, (title, pos, drop, kind) in zip(axes, strategies):
    ax.set_title(title, fontsize=11, fontweight="bold")
    gx, gy = grid_xy(np.arange(S))
    ax.scatter(gx, gy, s=5, c="#f3f4f8", edgecolors="none", zorder=0)   # slots vacíos, muy tenues
    ax.axhline(0.0, color="#ccc", lw=1.0, zorder=1)
    ax.text(COLS/2, WROWS + 1.4, "waiting room", ha="center", fontsize=8, color="#888")
    ax.text(COLS/2, -GROWS - 0.6, "assigned positions", ha="center", fontsize=8, color="#888")
    S_seat.append(ax.scatter([], [], s=22, linewidths=0.5, zorder=3))
    S_wait.append(ax.scatter([], [], s=18, linewidths=0.5, zorder=2))
    S_fly.append(ax.scatter([], [], s=40, linewidths=0.7, zorder=4))
    ax.set_xlim(-1, COLS); ax.set_ylim(-(GROWS + 1.2), WROWS + 2.2)
    ax.set_xticks([]); ax.set_yticks([]); ax.set_facecolor("white")

legend = [Line2D([0],[0], marker='o', color='w', markerfacecolor=BLUE, label='bot (fast)', markersize=8),
          Line2D([0],[0], marker='o', color='w', markerfacecolor=RED, label='person (slow)', markersize=8)]
fig.legend(handles=legend, loc='lower center', ncol=2, frameon=False, fontsize=9,
           bbox_to_anchor=(0.5, 0.0))
sup = fig.suptitle("", fontsize=14, fontweight="bold")

def put(sc, xy, hmask):
    if len(xy):
        sc.set_offsets(np.array(xy))
        sc.set_facecolors(np.where(hmask, RED, BLUE))
        sc.set_edgecolors(np.where(hmask, "#4a0008", "none"))   # rojos con borde para resaltar
    else:
        sc.set_offsets(np.empty((0, 2)))

def update(fi):
    t = ts[fi]
    for s_seat, s_wait, s_fly, (title, pos, drop, kind) in zip(S_seat, S_wait, S_fly, strategies):
        arrived = arr <= t
        seated = arrived & (t >= drop + FLY)
        flying = arrived & (t >= drop) & (t < drop + FLY)
        waiting = arrived & (t < drop)

        sx, sy = grid_xy(pos[seated])
        put(s_seat, list(zip(sx, sy)), is_human[seated])

        widx = np.where(waiting)[0]
        if kind == "rand":
            # pila barajada: el orden se re-baraja en cada ola (muestra el shuffle)
            cw = int(np.sum(wave_times <= t))
            widx = widx[np.random.default_rng(100 + cw).permutation(len(widx))]
        else:
            widx = widx[np.argsort(arr[widx])]       # fila ordenada por llegada
        wxy = [pile_xy(k) for k in range(len(widx))]
        put(s_wait, wxy, is_human[widx])

        fidx = np.where(flying)[0]
        fxy = []
        for i in fidx:
            gx1, gy1 = grid_xy(pos[i])
            fr = np.clip((t - drop[i]) / FLY, 0, 1)
            fxy.append((gx1, 0.0 + (gy1 - 0.0) * fr))
        put(s_fly, fxy, is_human[fidx])

    if t >= DUR:
        phase = "all admitted"
    elif t < BOTS_UNTIL:
        phase = "bots + people arriving"
    else:
        phase = "only people arriving now"
    sup.set_text(f"t = {min(t, DUR):4.1f} s      ({phase})")
    return S_seat + S_wait + S_fly

fig.tight_layout(rect=(0, 0.04, 1, 0.94))
anim = FuncAnimation(fig, update, frames=len(ts), interval=1000/FPS, blit=False)
anim.save(OUT, writer=PillowWriter(fps=FPS))
print(f"saved {OUT} ({len(ts)} frames)")
