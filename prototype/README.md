# FairQueue — Prototipo (OpenResty/Lua)

Prototipo funcional del algoritmo de FairQueue antes de portarlo al módulo C
(`ngx_http_fairqueue_module.so`). Valida, sobre un Nginx/OpenResty real, que:

1. La **posición no depende del orden de llegada** (muere la ventaja de velocidad).
2. La **penalización por volumen** (multi-cuenta/retry por device) neutraliza la
   ventaja de tener 100 identidades por humano — **sin bloquear** (no hay `403`).
3. La admisión se decide **100% server-side**: tampear el JS no permite colarse.

> Esto es un prototipo para iterar el algoritmo. El entregable final es un
> módulo dinámico en C instalable (`apt install` / `load_module`). El mapeo
> directiva → parámetro está en `openresty/lua/config.lua`.

## Algoritmo

Por cada request, en O(1) y sin almacenar la cola:

```
frac      = HMAC(secret, event_id .. devid)      ∈ [0,1)   # anclado al DEVICE
base      = floor(frac * N)            # N = nº de PARTICIPANTES (devices)
penalty   = (cuentas_del_device - 1) * penalty_fraction * N   # fracción de N (§5)
aging     = floor(segundos_esperando * aging_per_sec)   # first_seen del device
posición  = max(0, base + penalty - aging)

cursor    = rate_per_sec * max(0, now - start)
admitido  ⟺ posición <= cursor
```

- **base**: tu lugar sale de un hash determinístico proyectado sobre cuánta
  gente hay. No del orden de llegada. HMAC con secreto ⇒ no se puede predecir ni
  "minar" una identidad con buena posición offline.
- **freeze anti-reroll**: `frac` se ancla al **device** (no a la identidad), así
  que F5 o borrar la cookie de identidad dan **el mismo número**
  (detalle y verificación en `analysis/REPORT.md` §9). `N`
  cuenta participantes/devices (no inflable por multicuenta). Re-tirar exige un
  device nuevo ⇒ el reroll no se elimina, se **encarece**.
- **penalty**: lo que hace que el hash resista el volumen. Un bot con 50 cuentas
  en el mismo device recibe `49 * penalty_per_account` posiciones de castigo en
  TODAS sus identidades, sin importar su mejor hash.
- **aging**: recupera prioridad con el tiempo. Evita starvation y amortigua
  falsos positivos.
- **cursor**: avanza con el reloj al ritmo `rate`. El backend solo ve ese caudal.

## Modelo de confianza (importante)

El JavaScript de la sala de espera **no concede acceso**; es solo UX. La
autoridad es el `access_by_lua` (`fairqueue.gate`), que recalcula
`posición <= cursor` en el servidor en cada request y solo entonces emite un
**token firmado HMAC** (`fq_adm`, ligado a la identidad y con caducidad). Ese
token es lo único que deja pasar al `proxy_pass`.

- Tampear el JS para saltar a `/checkout` antes de tiempo ⇒ sin token válido ⇒
  `gate()` reevalúa y devuelve al waiting room.
- Falsear el JSON de `/__fairqueue/status` en el cliente ⇒ no genera token
  (no se puede firmar sin el secreto).
- Funciona **sin JS**: un refresh de `/checkout` reevalúa en servidor.

## Componentes

```
openresty/
  nginx.conf              # /checkout (gate), /waiting-room, /__fairqueue/status
  lua/config.lua          # parámetros = directivas del módulo C
  lua/fairqueue.lua       # núcleo: identidad, posición, token, gate/status
  html/waiting-room.html  # sala de espera (polling + modelo de confianza)
backend/nginx.conf        # backend de negocio simulado (no conoce FairQueue)
sim/model_check.lua       # prueba OFFLINE del modelo (hash vs hash+penalty)
sim/simulate.py           # prueba EN VIVO por HTTP (humanos vs bots), métricas
docker-compose.yml        # edge (FairQueue) + backend
```

## Cómo correrlo

### Local (Docker)

```bash
cd prototype
docker compose up -d                 # edge en http://localhost:8080
python3 sim/simulate.py --humans 150 --bots 15 --accounts-per-bot 10 --duration 40
```

Abrir `http://localhost:8080/checkout` en el navegador para ver la sala de espera.

Variables (mapeo a directivas del módulo C):

| env                      | directiva                     | default |
|--------------------------|-------------------------------|---------|
| `FQ_RATE_PER_SEC`        | `fairqueue_rate`              | 1       |
| `FQ_START_EPOCH`         | `fairqueue_start`             | arranque|
| `FQ_WAITING_URI`         | `fairqueue_waiting_uri`       | /waiting-room |
| `FQ_PENALTY_FRACTION`    | `fairqueue_penalty`           | 0.02    |
| `FQ_AGING_PER_SEC`       | `fairqueue_aging`             | 0.5     |
| `FQ_TOKEN_TTL`           | `fairqueue_token_ttl`         | 300     |
| `FQ_SECRET`              | `fairqueue_secret`            | (demo)  |
| `FQ_WAITING_START`       | `fairqueue_waiting_start`     | 0 (abierto) |
| `FQ_WINDOW_HEADROOM`     | `fairqueue_window_headroom`   | 0.2     |
| `FQ_AGING_CAP_FRACTION`  | `fairqueue_aging_cap`         | 0.1     |
| `FQ_ALLOCATION`          | `fairqueue_allocation`        | hash    |
| `FQ_MAX_DEVICES_PER_IP`  | `fairqueue_max_devices_per_ip`| 64      |
| `FQ_TRUST_XFF`           | `fairqueue_trust_xff`         | off (demo:on) |
| `FQ_COOKIE_SECURE`       | `fairqueue_cookie_secure`     | off     |
| `FQ_RISK_HEADER`         | `fairqueue_risk_header`       | (off)   |
| `FQ_RISK_WEIGHT`         | `fairqueue_risk_weight`       | 0.5     |
| `FQ_HOST_PORT`           | (puerto publicado del host)   | 8080    |

**Detección enchufable:** con `FQ_RISK_HEADER=X-Risk-Score`, FairQueue lee un
score `0..1` de un upstream de confianza y lo suma como penalización
(`+ risk*risk_weight*N` posiciones) — nunca bloquea, falla seguro. En modo experto
se puede pasar un hook Lua `risk_fn` por location en vez del header. Ver `REPORT.md §0`.

### Validación offline (sin red)

```bash
lua sim/model_check.lua
```

Demuestra por qué el hash solo no basta:

```
(a) solo hash  penalty=0     humano=0.16  bot=0.56  AdvantageRatio=3.50
(b) hash+penalty=250         humano=0.16  bot=0.00  AdvantageRatio=0.00
```

## Resultados (corrida en vivo, rate=5/s)

150 humanos vs 15 bots × 10 cuentas (mismo device), 40s:

```
Humanos admitidos:        139/150  (93%)
Bots admitidos:           10/15        (nunca bloqueados)
Posición inicial mediana  humano=86   bot(mejor-de-10)=2258
Bot Advantage Ratio:      0.07         (ideal <= 1.0)
```

El bot no es bloqueado; su ventaja desaparece.

## Limitaciones (honestas)

- La señal de volumen es el **device cookie**. Un **bot distribuido** (device
  fresco por identidad, sin compartir cookie) evade la penalización por device.
  Es el caso difícil que el concepto reconoce; mitigaciones (clustering por
  IP/ASN, señales de comportamiento) van en versiones posteriores.
- Con `penalty` alto se *sobre-penaliza* (AdvantageRatio → 0). Hay que tunear
  hacia ~1.0 para minimizar impacto de falsos positivos; el aging ayuda.
- Prototipo en `lua_shared_dict` = 1 nodo. El port a C mantiene shared memory;
  multi-nodo (Redis) es v1.x.

## Siguiente paso

Portar este algoritmo a `ngx_http_fairqueue_module.c`:
directivas (`fairqueue`, `fairqueue_rate`, `fairqueue_start`, …), `fairqueue_zone`
en shared memory, handler en fase `NGX_HTTP_ACCESS_PHASE`, y empaquetado
`.so` + instalador.
