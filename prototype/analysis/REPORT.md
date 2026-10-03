# FairQueue — Validación matemática/estadística de la fórmula

Análisis analítico + Monte Carlo del mecanismo de posición, barriendo volumen,
cuentas por bot, penalización, rate, aging y tiempo. Reproducible:

```bash
python3 prototype/analysis/model.py      # imprime este análisis + CSVs en out/
```

Todo se apoya en **stdlib** (sin numpy): el modelo admite una forma cerrada que
hace la validación barata y, a la vez, explica *por qué* se comporta así.

---

## 0. Tesis, contribución y posicionamiento

**Problema.** En drops de alta demanda, un esquema FIFO premia la velocidad: el
que automatiza más rápido gana. Y distinguir bot de humano *a ciegas* (sin
señales externas) es un problema **irresoluble** y adversarial.

**Giro.** FairQueue no intenta responder *"¿eres un bot?"* (irresoluble), sino
*"¿cómo reparto de forma justa cuando NO lo sé?"*. Bajo ignorancia total, la
asignación **maximalmente justa** es la **lotería uniforme**: tratar a toda
identidad por igual y azarizar. Un clasificador equivocado haría daño; no
clasificar no puede equivocarse. Es **mechanism design**, no detección.

**Contribución (el primitivo, universal y reutilizable).** Un módulo de Nginx
*drop-in* que da un **waiting room justo** sin que el integrador escriba código ni
toque su backend:
- **Asignación por hash congelado** (`frac=HMAC(secreto, event_id+device)`):
  elimina la ventaja de **velocidad** (la posición no depende de cuándo llegas) y
  de **predicción** (no se puede minar offline; solo comprar boletos a ciegas).
- **Ventanas incrementales / sectores** con `headroom`: gotean la admisión en el
  tiempo; nadie acapara de golpe; un late-joiner con buen hash cae en un hueco de
  una ventana temprana.
- **Admisión acotada a `rate`**: el backend **solo ve la tasa configurada** — no
  lo bombardean, no hay sell-out instantáneo. Es protección de backend, gratis.

**Posicionamiento.** FairQueue es **control de admisión / fair-queuing**, NO un
anti-bot. La señal de riesgo (volumen por device/IP) es un **baseline simple y
deliberadamente torpe**, pensado para **extenderse**: cada integrador enchufa sus
propias fuentes (scores de fraude, reputación ASN/WAF, CAPTCHA, antigüedad de
cuenta) que ajustan la penalización. La calidad de mitigación de bots **degrada y
mejora de forma elegante** con las señales que aporte el integrador; el primitivo
justo+protección-de-backend **vale por sí solo** sin ninguna de ellas.

**Hipótesis (formal).**
> Un mecanismo de admisión basado en **asignación temporal determinística por
> hash con secreto** y **ventanas dinámicas incrementales**, con admisión acotada
> por tasa, produce una distribución **justa por identidad, neutral a la
> automatización y con carga de backend acotada**, **sin requerir clasificación
> bot/humano**. Convierte la ventaja de automatización (velocidad, gratis,
> determinista, instantánea) en **costo de capital** (lineal en identidades/IPs,
> probabilístico, goteado). La mitigación de abuso por volumen depende de una
> única suposición — que **fabricar identidades cueste** — mucho más débil y
> alcanzable que "saber detectar bots", y reforzable con señales externas del
> integrador.

**Alcance honesto.** La justicia es *por identidad*: iguala a todos los que tienen
una. La única palanca de ventaja restante — tener muchas identidades — se paga en
devices/IPs (ver §9, §12). Si las identidades fueran gratis e infinitas, el
volumen ganaría por conteo; de ahí el cap/costo por IP como baseline y las señales
externas como refuerzo. Eso es un parámetro económico a calibrar, no un fallo del
mecanismo.

---

## 1. Fórmula y forma cerrada

Por identidad (llegada en bloque, `start=0`):

```
posición(t) = max(0, floor(frac·N) + pen − floor(aging·t))
cursor(t)   = rate·t
pen         = (cuentas_device − 1)·P
admitido    ⟺ posición(t) ≤ cursor(t)
```

Igualando `posición(t)=cursor(t)` (continuo) sale el **tiempo de admisión**:

```
t*_i = (floor(frac_i·N) + pen_i) / (rate + aging)
```

De aquí, **admitido en horizonte T ⟺ floor(frac_i·N) + pen_i ≤ K**, con
**presupuesto** `K = (rate + aging)·T` (posiciones liberadas hasta T).

Dos consecuencias inmediatas:
- **El aging suma a la tasa efectiva**: la cola se drena a `rate+aging`, no a
  `rate`. Acota la espera máxima a `N/(rate+aging)` (⇒ sin starvation) pero
  **aumenta la carga real admitida** por el backend. Hay que mantenerlo modesto.
- Todo depende de **tres grupos adimensionales**:
  `ρ = K/N` (fracción admitida, crece con el tiempo), `p = P/N`, `k` (cuentas/bot).

## 2. Predicciones cerradas (frac ~ U(0,1))

```
P(admite | humano)    = min(1, ρ)
P(admite | id de bot) = clamp(ρ − (k−1)p, 0, 1) =: q
P(admite | dueño bot) = 1 − (1 − q)^k            # mejor de k identidades
Advantage Ratio       = [1 − (1−q)^k] / min(1, ρ)
```

## 3. Validación: Monte Carlo ≈ teoría

El modelo exacto (con floors, colisiones, `min` de k) reproduce las fórmulas:

| ρ | p | humano sim/teo | id-bot sim/teo | dueño sim/teo |
|---|---|---|---|---|
| 0.20 | 0.00 | 0.201 / 0.200 | 0.202 / 0.200 | 0.899 / 0.893 |
| 0.20 | 0.02 | 0.201 / 0.200 | 0.022 / 0.020 | 0.194 / 0.183 |
| 0.40 | 0.02 | 0.402 / 0.400 | 0.221 / 0.220 | 0.922 / 0.917 |

→ La forma cerrada describe el sistema; podemos razonar analíticamente.

## 4. La ventaja de volumen y cómo se mata (penalización)

Con `p=0` (solo hash), el bot conserva ventaja por **volumen** (toma el mejor de
k hashes). AR(dueño) con ρ=0.2:

| p=P/N | k=2 | k=5 | k=10 | k=50 |
|---|---|---|---|---|
| 0.000 | 1.80 | 3.36 | 4.46 | 5.00 |
| 0.010 | 1.72 | 2.91 | 3.44 | 0.00 |
| 0.020 | 1.64 | 2.36 | **0.91** | 0.00 |
| 0.040 | 1.47 | **0.92** | 0.00 | 0.00 |
| 0.080 | **1.13** | 0.00 | 0.00 | 0.00 |

**Umbral de diseño:** la ventaja se neutraliza (AR≈1) con

```
p* ≈ ρ / k        ⟺     P* ≈ K / k
```

Intuición: hacer que el castigo de `k` cuentas (`(k−1)P`) iguale al presupuesto
de admisión `K`. Más allable: por encima de `p = ρ/(k−1)` hay **shutout** (AR→0).

> **Matiz honesto:** `k=2` es casi indistinguible de un humano (AR sigue >1
> hasta p grande). El mecanismo castiga el **abuso de volumen**, no a quien tiene
> 2 cuentas. Correcto por diseño.

## 5. Escalabilidad en volumen (N) — hallazgo clave

La penalización **debe expresarse como fracción de N**, no como constante:

**Fraccional `P = 0.015·N`** → AR invariante en N (converge a la teoría):

| N | AR dueño (sim) | teoría |
|---|---|---|
| 1 000 | 2.02 ± 0.23 | 2.45 |
| 10 000 | 2.44 ± 0.05 | 2.45 |
| 100 000 | 2.46 ± 0.01 | 2.45 |

**Absoluta `P = 250`** → la penalización se diluye y el bot recupera ventaja:

| N | p=P/N | AR dueño |
|---|---|---|
| 1 000 | 0.250 | 0.00 |
| 20 000 | 0.0125 | 3.00 |
| 100 000 | 0.0025 | 4.29 |

→ **Recomendación para el módulo C:** `penalty = (device_accounts−1)·p·N(t)`,
con `N(t)` = total de identidades en la zona (ya se trackea en shared memory).
`p` configurable (`fairqueue_penalty ~ ρ*/k_objetivo`, típico 0.01–0.03).

## 6. Dinámica en el tiempo

Escenario N=6000, rate=8.33/s (500/min), aging=0.5/s, p=0.03, k=10:

- **Espera humana** (bounded, sin starvation): `p50=331s`, `p95=644s`, `max=679s`.
- **Ventana escasa** `t ≤ 136s` (ρ=0.2, *cuando el recurso existe*):
  humanos 19% admitidos, **dueños-bot 0%**. Los bots quedan fuera de lo que importa.
- **Horizonte completo** (si se admitiera a todos): los bots reaparecen
  (mediana 234s vs humano 331s) porque el `min` de k hashes es potente.
  → **La defensa vive en la ventana escasa, no en el drenaje total.** En
  ticketing eso basta: las entradas se agotan con ρ pequeño.
- **Carga de backend** acotada a ~`rate+aging` (8.8/s), plana en el tiempo
  (`▆▆▇█▇▇▇▆▆▆▇▆`): no hay pico inicial de N. Es el objetivo central del sistema.

## 7. Jain's Fairness Index (humano vs dueño-bot)

| p=P/N | J | lectura |
|---|---|---|
| 0.00 | 0.71 | bots dominan |
| 0.01 | 0.76 | bots dominan |
| 0.03 | 0.50 | bots desfavorecidos (deseado) |

`J=1` = iguales. Aquí lo deseable es `J<1` con bot<human (el abuso no paga).

## 8. Guías de diseño que salen del análisis

1. **Penalización proporcional al volumen**: `P = p·N(t)`, `p ≈ ρ*/k_objetivo`
   (≈ 0.01–0.03). `ρ*` = fracción escasa (capacidad/demanda).
2. **Medir éxito en la ventana escasa** (ρ pequeño), no en el drenaje total.
3. **aging modesto**: acota la espera (anti-starvation, anti-falsos-positivos)
   pero aumenta la carga admitida (`rate+aging`). Mantener `aging ≪ rate`.
4. El mecanismo ataca **volumen alto**; 2 cuentas ≈ humano (aceptable).
5. Caso no cubierto: **bot distribuido** (device fresco por identidad ⇒ k=1 por
   device ⇒ sin penalización). Requiere señales adicionales (IP/ASN,
   comportamiento) en v1.x; es ortogonal a esta fórmula.

## 9. Anti-reroll (freeze) y economía del ataque

El usuario que sabe que la asignación no es secuencial intentará **re-tirar** el
número (F5 / borrar cookies) hasta obtener uno mejor. Se neutraliza **anclando el
número al device**, no a la identidad:

```
frac = HMAC(secret, event_id + devid)     # no a rid
N    = nº de PARTICIPANTES (devices)       # no de identidades (no inflable)
first_seen anclado al device               # re-identificarse no resetea el aging
```

Verificado en el stack real (`/__fairqueue/status`):

| acción | slot | accounts | penalty | posición |
|---|---|---|---|---|
| primer contacto | 477502 | 1 | 0 | 5 |
| F5 ×3 | 477502 | 1 | 0 | 5 |
| borrar `fq_id` #1 | 477502 | 2 | 250 | 255 |
| borrar `fq_id` #2 | 477502 | 3 | 500 | 505 |
| device nuevo | 633205 | 1 | 0 | 7 |

→ F5 = idéntico. Borrar identidad = mismo número **+ penalización** (estrictamente
peor). Re-tirar exige un **device nuevo**.

**No se elimina el reroll: se encarece.** Cada device = 1 tirada uniforme, así que
para caer en la ventana escasa ρ:

| ρ | E[devices] 1 éxito | devices 90% éxito |
|---|---|---|
| 0.20 | 5.0 | 10.3 |
| 0.05 | 20.0 | 44.9 |
| 0.01 | 100.0 | 229.1 |

Colocar M identidades adelante cuesta ~**M/ρ devices** (ej. 100 bots con ρ=0.05 ⇒
~2000 devices/IPs). Multicuenta en el mismo device es contraproducente (baja la
prob. a `ρ−(k−1)p` y suma penalización), así que el atacante racional usa 1 cuenta
por device y muchos devices ⇒ **costo lineal en nº de slots buenos** y escalada
obligada a botnet distribuida. Escalera de costo:

```
1. F5 misma cookie ............ gratis      → bloqueado (freeze)
2. borrar cookies / incógnito . mismo device→ bloqueado (freeze + penalty)
3. navegadores/perfiles ....... 1 roll/device
4. máquinas/IPs distintas ..... 1 roll/IP    → señales IP/ASN/comportamiento (v1.x)
```

Es el **principio económico** (concepto §31): no clasificar bot/humano perfecto,
sino subir `coste_atacante / beneficio` hasta que el abuso deje de pagar.

## 10. Ventana dinámica y fase de registro (transitorio de llegada)

**Dinamismo (deseado):** la posición usa `N(t)` vivo, así que la ventana
`N(t)/rate` se **ensancha** al crecer la demanda y se reparte por hash, no por
llegada. Quien sigue esperando cuenta en `N`; cada nueva llegada lo sube. Un
late-joiner con buen hash entra adelante aunque otros lleven rato esperando — la
velocidad no compra posición.

**Transitorio (el riesgo):** el hash es justo *dentro de la población presente*.
Si se drena mientras la cola se forma, en los primeros segundos la población es
casi pura bots (llegan primero) y el denominador `N` es chico ⇒ posiciones
deflactadas ⇒ fuga de bots. Simulación (bots en 3s, humanos en 120s, hash puro
sin penalización; bots = 20% de la población):

| política | ventana escasa | bots admitidos | bot_share |
|---|---|---|---|
| cursor desde t=0 (sin registro) | 0–62s | 172/490 | **35%** (fuga) |
| cursor tras formarse la cola | 125–188s | 93/476 | **20%** (su cuota real) |

**Fix — fase de registro:** mantener `cursor = 0` hasta `sale_start` para que la
cola se forme antes de drenar. Ya está en el gate
(`cursor = rate·max(0, now − sale_start)`); operacionalmente basta abrir la sala
de espera antes del `sale_start`. Concepto §8: `waiting_start` (abre cola) <
`sale_start` (arranca cursor). Tras `sale_start`, el dinamismo continúa.

→ Directivas: `fairqueue_waiting_start` (abre registro, opcional, UX de cuenta
regresiva) y `fairqueue_start` (= `sale_start`). `fairqueue_window auto` (= N/rate
dinámico, default) | `<seg>` (fijo).

## 11. Validación en vivo end-to-end (stack real, ciclo registro→venta)

Modelo completo desplegado (OpenResty + shared memory + cookies firmadas +
freeze por device + penalización fraccional + headroom + fase de registro).

**Fase de registro** (snapshot real, cursor=0): `{phase:registration, cursor:0,
total:271, waiting_now:271, position:29, slot:91026, sale_in:1, window_eta:55}`
— la cola se forma antes de drenar; `base≈frac·N·1.2` y `window_eta≈N·1.2/rate`
cuadran con las fórmulas.

**Ventana escasa** (150 humanos, 15 bots multicuenta ×10 mismo device, 10 bots
distribuidos ×10 devices; ρ≈0.27):

| grupo | éxito | pos. inicial mediana | Advantage Ratio |
|---|---|---|---|
| humano (1 device) | 0.27 | 66 | 1.00 |
| bot multicuenta (mismo device) | 0.20 | 113 | **0.73** |
| bot distribuido (devices distintos) | 0.90 | 16 | **3.29** |

Lectura:
- **Velocidad**: eliminada (hash). Llegar primero no da posición.
- **Volumen en el mismo device**: eliminado. Con `frac` anclado al device, las 10
  cuentas comparten número (no hay "mejor de 10") y encima cargan penalización ⇒
  AdvRatio 0.73 (peor que un humano).
- **Volumen distribuido** (device/IP distinto por identidad): sí recupera ventaja
  (AdvRatio 3.29, mejor-de-10), pero **cuesta 10 devices/IPs reales por bot**.
  Por device, la tasa de éxito es ~la de un humano: no hay ventaja por unidad,
  solo compra de más boletos. Ese es el **frontera económica** (§9): no es un
  bloqueo, es costo lineal en infraestructura — justo lo que buscamos (§31 del
  concepto). Lo que ataca este caso son señales IP/ASN/comportamiento (v1.x).

## 12. Threat model (2 rondas de red-team adversarial)

Dos rondas de 3 agentes adversariales (cripto/identidad, algorítmico/económico,
implementación/DoS) leyendo el código real.

**Ronda 1 → arreglado y verificado en ronda 2 (FIX-OK):**
- Admisión antes de `sale_start` (ahora `admitted = started AND position≤cursor`).
- Aging "madrugador": ya solo corre desde `sale_start` y topado (ahora a 0.1·span).
- Token replayable entre colas: firma ahora liga `event_id+scope+device+rid+exp`.
- Headers `X-FairQueue-*` del cliente: limpiados hacia el backend.
- Standing fino oculto en registro; `frac` 48-bit; `ct_eq` tiempo-constante; `rate>0`.
- Secreto por defecto: ahora **fail-closed** (aborta el arranque sin `FQ_SECRET`).
- Cap por IP ahora **atómico** (incr-then-check, sin TOCTOU multi-worker).
- Token ligado a **device**: robar solo `fq_adm` (sin `fq_dev`) no sirve.

**Limitaciones FUNDAMENTALES (no cerrables in-band; requieren v1.x):**
- **Bot distribuido (1 device / 1 IP por identidad) → `volume=1` → penalización 0.**
  Toma el mejor hash de su cartera (best-of-k). Advantage Ratio ≈ `[1−(1−ρ)^k]/ρ`
  (~3.3 con k=10, ρ=0.2). El costo es ~`M/ρ` IPs residenciales (céntimos c/u). Para
  ticketing de alto valor ese costo NO disuade. **La tesis "el volumen no da
  ventaja" solo se sostiene contra volumen torpe (mismo device/IP); el volumen
  distribuido gana.** Cerrarlo exige señales externas (reputación IP/ASN,
  prueba-de-humanidad/PoW, cuentas con historial) — ortogonal a la fórmula.
- **Minado de slots en fase de venta:** `status` revela `position` en venta; crear
  devices y quedarse con los de baja posición. Acotado por el cap/IP, pero el cap
  es evadible (ver XFF) y en todo caso es best-of-k.
- **Tensión NAT ↔ anti-abuso:** el cap/penalización por IP excluye o penaliza a
  humanos legítimos tras CGNAT/corporativo. Bajar el cap frena bots pero mata NAT;
  subirlo salva NAT pero reabre el minado. Sin reputación/ASN no hay punto bueno.

**Requisitos de DESPLIEGUE (config, no bug de código):**
- `trust_xff` debe estar **off** en edge expuesto (si on, el cliente forja la IP y
  evade el cap + puede hacer lockout dirigido a una víctima). Solo on detrás de un
  proxy de confianza que **reescriba** XFF; tomar el hop de confianza, no el 1º.
- Cada cola debe usar un `scope` único; rotar `event_id` (idealmente un nonce por
  drop que además entre en `frac`) para que no se reuse la cartera entre ventas.
- Dimensionar el `lua_shared_dict` al aforo: `N` no decrementa (fantasmas) y la
  eviction corrompe el estado. v1.x: conteo activo por heartbeat + tope global.

**Veredicto (marco correcto — el objetivo NO es bloquear al 100%, es encarecer):**
- **Predecibilidad:** eliminada — `frac=HMAC(secreto,·)` no se puede minar offline;
  el atacante solo puede comprar boletos a ciegas.
- **Velocidad:** eliminada — llegar primero no da puesto; late-joiners (bot o humano)
  caen mejor o peor de forma no predecible.
- **Acaparamiento instantáneo:** eliminado — la admisión gotea a `rate` repartida en
  la ventana; nadie llena la cola de golpe (protege el backend, no hay sell-out).
- **Costo:** de ≈0 (un script) a **~1/ρ IPs por ticket** (cada IP = 1 boleto con
  prob ρ). El sistema es **neutral a la automatización**: no premia scripts, premia
  capital. Un bot con k IPs tiene AdvRatio≈[1−(1−ρ)^k]/ρ, pero **por IP ≈ 1×** que
  un humano → su única ventaja es gastar más, que es justo el costo que buscamos.

Lo que queda es **calibración**, no fallo: `1/ρ × precio_IP` debe doler frente al
valor del ticket (perilla ρ/headroom), la tensión NAT se balancea (o se suma
reputación ASN en v1.x), y los requisitos de despliegue (trust_xff off, scope único,
rotar event_id, dimensionar el dict) deben respetarse. FairQueue es un *waiting room
que elimina velocidad/predecibilidad y convierte el volumen en costo de capital
lineal* — exactamente su tesis económica (§31 del concepto), no un anti-bot absoluto.

## 12-bis. Tercera ronda de red-team (post-fixes R2 + hook de riesgo)

Verificó que los fixes de R2 están correctos (cap por IP **atómico** real sin TOCTOU;
N contado **después** del cap; device-binding consistente; fail-closed; handoff
status→checkout intacto) y halló grietas nuevas, ya **arregladas**:

- **[ARREGLADO] Aging reintroducía velocidad de REGISTRO.** Aun anclado a
  `sale_start`, el presente-al-abrir tenía hasta `0.1·span` de ventaja sobre un
  late-joiner → invertía el hash en una banda. **Fix:** el aging ahora erosiona
  **solo la penalización** (`position = base + max(0, penalty − aging)`): un
  honesto (`penalty=0`) no tiene término temporal → hora de llegada 100%
  irrelevante; el aging solo recupera falsos positivos. Restaura la afirmación §10.
- **[ARREGLADO] `event_id` fijo → cartera reusable entre drops.** Ahora el hash y
  el token usan `event_key = event_id:scope:start_epoch` → **rotan por drop**; no
  se precomputa/reusa cartera ni se replayan tokens entre eventos.
- **[ARREGLADO] `status()` con efectos (CSRF de encolado).** Ahora es
  **solo-lectura**: no registra, no emite token, no acuña cookies. Un
  `<img src=/__fairqueue/status>` de terceros ya no encola víctimas ni infla N.
- **[ARREGLADO] NaN del hook de riesgo** → `position=NaN` → waiting permanente:
  guard `risk~=risk → 0`. Y el `risk_header` **solo se honra con `trust_xff`**
  (en edge expuesto se ignora, no da falsa sensación de defensa).
- **[config seguro] `trust_xff` default = 0** (antes 1 en el compose). El sim pasa
  `FQ_TRUST_XFF=1` explícito. Cierra la evasión del cap / lockout dirigido por XFF
  en un despliegue "tal cual".

**Umbral económico (honesto, H1).** El ataque más barato HOY es el distribuido
1-device/1-IP (`volume=1` → penalización 0, best-of-k entre IPs). Con proxies
residenciales (~$0.01–0.10/IP) y ρ, el **costo por ticket ≈ `precio_IP / ρ`**
(≈$0.05–0.50 a ρ=0.2). Para reventa de alto valor **eso no disuade**: a ρ típicos
de ticketing el mecanismo **requiere** señales externas (reputación ASN/IP con
historial, PoW) vía el hook — el hook NO es respuesta al distribuido por sí mismo
(un proxy residencial limpio da `risk≈0`). FairQueue sube el costo de ~0 (FIFO) a
`precio_IP/ρ` y mata velocidad/predecibilidad/acaparamiento; el resto es la capa
del integrador.

**Tensión NAT (H4, cuantificada).** La penalización por `ip_devices` hace shutout
de NAT a partir de ~`ρ/penalty_fraction + 1` usuarios/IP (≈11 con p=0.02, ρ=0.2).
Es el reverso de frenar el minado concentrado (que sí queda cerrado). Sin señal
ASN no hay punto bueno; calibrar `penalty_fraction`/`max_devices_per_ip` al perfil
de red, o excluir `ip_devices` del volumen cuando haya ASN de NAT conocido (v1.x).

> Nota de verificación: un agente afirmó que `dict:incr(...,ttl)` renueva el TTL en
> cada incremento (ipdev "nunca expira"). **Incorrecto**: en OpenResty el `init_ttl`
> solo aplica al CREAR la clave; `ipdev` expira 6h tras su creación. El vector real
> de lockout por IP es el spoof de XFF (cerrado con `trust_xff=0` por default).

## 13. Artefactos

`out/validation.csv`, `penalty_sweep.csv`, `volume_fractional.csv`,
`volume_absolute.csv`, `timeline.csv` — datos crudos para graficar aparte.
