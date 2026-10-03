# FairQueue — Concepto de cola virtual adaptativa para Nginx

## 1. Idea general

**FairQueue** es una capa de control de tráfico para eventos de alta demanda, diseñada para instalarse directamente sobre una infraestructura Nginx existente.

El objetivo es proteger rutas sensibles —por ejemplo `/buy`, `/reserve` o `/checkout`— sin modificar el backend de negocio y sin obligar al operador a reemplazar su infraestructura.

La propuesta combina:

- Waiting room virtual
- Asignación temporal determinística
- Control de tasa de admisión
- Protección del backend ante picos de tráfico
- Penalización progresiva de comportamiento automatizado
- Priorización no-FIFO basada en riesgo
- Identificación persistente de dispositivo/sesión
- Reducción de la ventaja obtenida por bots, múltiples cuentas o reintentos agresivos

El principio central es:

> Mientras no sea el turno del usuario, el request no debe llegar al backend de negocio.

---

# 2. Problema

En ventas de entradas de alta demanda, miles o cientos de miles de usuarios pueden intentar comprar simultáneamente.

Un sistema tradicional tiende a favorecer:

- quien llega primero;
- quien genera requests más rápidamente;
- quien puede mantener muchas sesiones;
- quien crea múltiples cuentas;
- quien utiliza automatización;
- quien dispone de mayor capacidad computacional.

Un esquema FIFO tradicional puede transformar la velocidad de automatización en una ventaja directa.

Ejemplo:

```text
10:00:00.001 bot
10:00:00.002 bot
10:00:00.003 bot
...
10:00:01.500 usuario humano
```

El bot puede ocupar posiciones tempranas simplemente por generar requests más rápido.

FairQueue busca romper esa relación:

```text
más velocidad
!=
mejor posición
```

e incluso:

```text
comportamiento sospechosamente automatizado
→
peor prioridad
```

---

# 3. Arquitectura propuesta

```text
                    Internet
                       |
                       v
                Nginx existente
                       |
                FairQueue Module
              /                 \
             /                   \
      todavía espera           admitido
           |                       |
           v                       v
     Waiting Room              Backend
                               existente
```

El backend de la aplicación no necesita conocer la existencia de FairQueue.

Puede seguir siendo:

- Django
- Rails
- Laravel
- Node.js
- Java
- .NET
- Go
- cualquier servicio HTTP existente

FairQueue opera exclusivamente como una capa de admisión.

---

# 4. Instalación

La experiencia ideal debería parecerse a cualquier otro módulo dinámico de Nginx.

Ejemplo:

```bash
sudo apt install nginx-module-fairqueue
```

o mediante un instalador:

```bash
curl -fsSL https://fairqueue.dev/install.sh | sudo sh
```

El instalador podría detectar:

- versión de Nginx;
- arquitectura;
- distribución Linux;

y descargar el módulo compatible.

Ejemplo:

```text
ngx_http_fairqueue_module.so
```

Configuración:

```nginx
load_module modules/ngx_http_fairqueue_module.so;
```

Luego proteger una ruta debería requerir pocas líneas:

```nginx
location /checkout {
    fairqueue on;

    proxy_pass http://backend;
}
```

---

# 5. Configuración propuesta

La sintaxis debería resultar familiar para alguien acostumbrado a módulos como `limit_req`.

Ejemplo:

```nginx
http {

    fairqueue_zone tickets
        zone=tickets:20m
        capacity=500r/m;

    server {

        location /checkout {

            fairqueue zone=tickets;

            fairqueue_waiting_page /waiting.html;

            proxy_pass http://backend;
        }
    }
}
```

Una configuración más avanzada podría ser:

```nginx
fairqueue_zone tickets {
    capacity 500r/m;

    allocation hash;

    window auto;

    waiting_start 09:30;
    sale_start 10:00;

    penalty adaptive;
}
```

Luego:

```nginx
location /buy {
    fairqueue tickets;

    proxy_pass http://backend;
}
```

---

# 6. Waiting room

Cuando un usuario todavía no puede acceder:

```text
GET /checkout
```

FairQueue intercepta el request.

En lugar de enviarlo al backend:

```text
/checkout
   |
   v
FairQueue
   |
   v
waiting room
```

La waiting room puede ser:

- HTML estático;
- frontend personalizado;
- página servida desde CDN;
- aplicación externa;
- endpoint dinámico independiente.

Ejemplo:

```nginx
fairqueue_waiting_page /waiting.html;
```

También podría existir un endpoint:

```text
/__fairqueue/status
```

Respuesta:

```json
{
  "state": "waiting",
  "position": 18342,
  "estimated_access": "10:18:00",
  "estimated_wait_seconds": 428
}
```

Cuando el turno llega:

```json
{
  "state": "admitted",
  "redirect": "/checkout"
}
```

---

# 7. Asignación determinística

El objetivo no es mantener necesariamente una estructura gigantesca con todos los usuarios ordenados.

La posición o ventana base puede calcularse determinísticamente.

Ejemplo:

```text
bucket =
HMAC_SHA256(
    secret_seed,
    event_id + participant_id
)
%
bucket_count
```

Con esto:

- la asignación es reproducible;
- el usuario no puede predecir fácilmente su posición;
- el servidor no necesita almacenar toda la cola;
- el mismo participante obtiene consistentemente la misma asignación.

No se recomienda utilizar simplemente:

```text
SHA256(participant_id)
```

porque un atacante podría generar identidades hasta encontrar una con una posición favorable.

El uso de HMAC con un secreto evita ese problema.

---

# 8. Ventana dinámica

La ventana de espera no debería estar fijada arbitrariamente en 30 minutos.

Debe depender de:

```text
usuarios esperando
/
capacidad de admisión
```

Ejemplo:

```text
window_seconds =
ceil(
    waiting_users /
    admission_rate_per_second
)
```

Si la capacidad es:

```text
100 usuarios/minuto
```

entonces:

```text
5 usuarios
→ aproximadamente 3 segundos

500 usuarios
→ aproximadamente 5 minutos

3000 usuarios
→ aproximadamente 30 minutos
```

La cola se expande automáticamente cuando aumenta la demanda y se contrae cuando hay poca demanda.

---

# 9. Asignación temporal

Una vez calculada la ventana:

```text
slot =
HMAC(secret, participant_id)
%
window_seconds
```

y:

```text
eligible_at =
sale_start + slot
```

Ejemplo:

```text
usuario A → 10:03:12
usuario B → 10:08:45
usuario C → 10:17:02
```

Así, miles de personas que llegan simultáneamente pueden ser distribuidas a lo largo del período necesario para proteger el backend.

---

# 10. No-FIFO adaptive queue

FairQueue no tiene que funcionar como FIFO puro.

Cada participante puede tener:

```text
base_rank
```

y luego:

```text
effective_rank =
base_rank
+
risk_penalty
```

Un usuario legítimo:

```text
base_rank      = 400
risk_penalty   = 0
effective_rank = 400
```

Un patrón sospechoso:

```text
base_rank      = 10
risk_penalty   = 1200
effective_rank = 1210
```

El request no se bloquea.

Simplemente se atiende más tarde.

---

# 11. Penalización progresiva

Una característica central sería:

> El comportamiento automatizado no necesariamente genera un bloqueo; genera pérdida progresiva de prioridad.

Ejemplo:

```text
Intento 1 → posición 1200
Intento 2 → posición 2800
Intento 3 → posición 6500
Intento 4 → posición 14000
```

Esto crea un feedback loop negativo:

```text
intenta acelerar
      ↓
aumenta riesgo
      ↓
pierde posición
      ↓
reintenta
      ↓
pierde todavía más posición
```

Mientras un humano normal:

```text
entra
↓
espera
↓
avanza
```

---

# 12. Rate limiting inverso

El concepto puede entenderse como una especie de **rate limiting inverso**.

Rate limiting convencional:

```text
demasiadas requests
→ reject
```

FairQueue:

```text
actividad sospechosa
→ menor prioridad
→ mayor tiempo de espera
```

La automatización pierde competitividad en lugar de recibir necesariamente un `403`.

Esto reduce el feedback inmediato que el atacante recibe.

---

# 13. Señales de riesgo

En una primera versión no es necesario utilizar Machine Learning.

Pueden utilizarse señales simples:

```text
same_device_accounts
transition_speed
retry_frequency
concurrent_sessions
```

Ejemplo:

```text
5 cuentas
+
mismo navegador
+
mismo evento
+
actividad simultánea
```

puede incrementar la penalización.

O:

```text
acción A
→
acción B en 80 ms
sin teclado
sin mouse
sin touch
```

puede incrementar el riesgo.

Estas señales no deben utilizarse individualmente como prueba absoluta de automatización.

Son señales probabilísticas.

---

# 14. Device identity

FairQueue puede asignar un identificador persistente al navegador/dispositivo.

Ejemplo:

```text
device_id = D123
```

Luego:

```text
Account A → D123
Account B → D123
Account C → D123
Account D → D123
```

La existencia histórica de varias cuentas no necesariamente implica fraude.

Sin embargo:

```text
5 cuentas
mismo device
mismo evento
mismo minuto
```

es una señal mucho más relevante.

La penalización puede ser progresiva:

```text
primera cuenta → normal
segunda        → penalización leve
tercera        → penalización media
quinta         → penalización fuerte
```

---

# 15. Cluster risk

En versiones posteriores, FairQueue puede evaluar no solo cuentas individuales sino clusters.

Ejemplo:

```text
Account A
Account B
Account C
     \   |   /
      Device X
         |
         IP
         |
         network pattern
```

El sistema puede calcular:

```text
individual_risk
+
device_risk
+
cluster_risk
```

y traducirlo en una degradación de prioridad.

---

# 16. Aging

Una cola no-FIFO necesita evitar starvation.

Una persona con riesgo medio no debería quedar esperando para siempre.

Puede utilizarse:

```text
effective_priority += waiting_time_bonus
```

De esta forma:

```text
riesgo
→ retrocede inicialmente

pero

tiempo esperando
→ recupera progresivamente prioridad
```

Esto reduce el impacto de falsos positivos.

---

# 17. Estado

Para una primera versión enfocada en adopción fácil, FairQueue debería evitar dependencias externas.

Puede utilizar memoria compartida de Nginx.

Conceptualmente:

```text
fairqueue_zone main 32m;
```

En una primera implementación basada en OpenResty podría utilizarse:

```nginx
lua_shared_dict fairqueue 32m;
```

El estado mutable podría incluir:

```text
retry_count
device_penalty
active_accounts
event counters
risk score
```

La asignación principal puede permanecer stateless gracias al hash determinístico.

---

# 18. Roadmap de almacenamiento

## v0.x

```text
Single node
Shared memory
No Redis
No database
```

Objetivo:

```text
1 module
1 configuration
0 external dependencies
```

## v1.x

Agregar backend de estado intercambiable:

```text
SharedMemoryState
RedisState
```

La lógica interna podría abstraerse como:

```text
state.get(key)
state.set(key)
state.incr(key)
```

Esto permitiría distribuir FairQueue entre múltiples nodos en el futuro sin modificar el algoritmo.

---

# 19. Protección del backend

Uno de los objetivos centrales es que el backend reciba tráfico acotado.

Ejemplo:

```text
100,000 usuarios
        |
        v
     FairQueue
        |
        +---- 99,500 esperando
        |
        +---- 500/min
                 |
                 v
              backend
```

El backend no necesita dimensionarse para el pico inicial de 100,000 usuarios.

Solo necesita soportar la tasa configurada de admisión.

---

# 20. Tokens de admisión

Un usuario admitido podría recibir un token firmado:

```text
participant_id
event_id
eligible_at
expires_at
nonce
signature
```

Cuando intenta acceder directamente a:

```text
POST /checkout
```

FairQueue valida:

```text
¿token válido?
¿evento correcto?
¿ya es elegible?
¿no expiró?
```

Si falla:

```text
→ waiting room
```

Si pasa:

```text
→ proxy_pass backend
```

Esto evita saltarse la cola llamando directamente al endpoint protegido.

---

# 21. Demo experimental

El proyecto debería incluir una demo reproducible.

Ejemplo:

```bash
docker compose up
```

La demo puede simular:

```text
5000 usuarios humanos
1000 bots/revendedores
```

y comparar dos escenarios.

---

# 22. Escenario 1 — Nginx tradicional

Ejemplo:

```text
Reseller #1

arrival position: 10
effective position: 10
admitted at: 10:01
```

El bot obtiene ventaja por velocidad.

---

# 23. Escenario 2 — FairQueue

Mismo reseller:

```text
arrival position: 10

same-device penalty: +400
behavior penalty:    +350
retry penalty:       +473

effective position: 1233

admitted at: 10:31
```

Visualmente:

```text
#10
 ↓
#410
 ↓
#760
 ↓
#1233
```

El bot no fue bloqueado.

Su ventaja simplemente desapareció.

---

# 24. Landing/demo

Una landing puede mostrar ambos escenarios simultáneamente:

```text
SIMULACIÓN

5000 humans
1000 scalpers


NGINX NORMAL              FAIRQUEUE

Bot #1                    Bot #1

Initial #10               Initial #10
Final   #10               Penalty +1223
                           Final #1233

Access 10:01              Access 10:31
```

También se pueden mostrar métricas:

```text
Bot success rate
Human median wait
Backend peak RPS
p95 latency
requests rejected
requests admitted
```

---

# 25. Perfiles de simulación

El simulador debería incluir varios atacantes.

## Human

```text
1 account
1 device
natural timing
low retry rate
```

## Basic Bot

```text
high request rate
same device
perfect timing
```

## Retry Bot

```text
retries aggressively
```

## Multi-account Bot

```text
20 accounts
same browser/device
concurrent sessions
```

## Distributed Bot

```text
many devices
many identities
more human-like timing
```

El objetivo no es demostrar que todos los bots pueden eliminarse.

El objetivo es medir cuánto aumenta el coste de automatización.

---

# 26. Métricas académicas

Posibles métricas:

```text
bot success rate

human success rate

bot advantage ratio

median waiting time

p95 waiting time

backend requests/sec

backend CPU

backend memory

HTTP 5xx

queue stability
```

Una métrica interesante:

```text
Bot Advantage Ratio =

P(ticket | bot)
----------------
P(ticket | human)
```

Idealmente:

```text
≈ 1
```

o:

```text
< 1
```

si el comportamiento agresivo produce una desventaja.

---

# 27. Jain's Fairness Index

Puede utilizarse Jain's Fairness Index para evaluar fairness:

```text
J(x) = (Σxi)² / (n Σxi²)
```

Esto permite cuantificar la equidad de la distribución en lugar de evaluarla únicamente de manera cualitativa.

---

# 28. Hipótesis inicial de tesis

Una posible hipótesis:

> Un mecanismo de admisión basado en asignación temporal determinística y degradación dinámica de prioridad basada en riesgo reduce la ventaja obtenida mediante automatización agresiva frente a un esquema FIFO tradicional, manteniendo una carga acotada sobre el backend y sin incrementar significativamente la latencia de usuarios legítimos.

---

# 29. Experimentos

Variables independientes:

```text
usuarios:
1k
10k
100k

proporción de bots:
0%
10%
30%
50%

backend capacity:
100/min
500/min
1000/min

queue strategy:
FIFO
random
deterministic hash
risk-weighted
```

También:

```text
penalty strength
number of accounts/device
retry frequency
bot sophistication
waiting window
```

---

# 30. Contribución propuesta

FairQueue no intenta competir directamente con sistemas especializados de bot detection.

Su contribución principal es distinta:

```text
traditional:

risk
→ allow / challenge / block
```

FairQueue propone:

```text
risk
→ economic disadvantage
```

mediante:

```text
risk-weighted scheduling
```

En lugar de depender de una clasificación binaria perfecta:

```text
bot / human
```

FairQueue utiliza una degradación progresiva.

Esto permite trabajar con incertidumbre y reducir el impacto de falsos positivos.

---

# 31. Principio económico

El objetivo no es necesariamente eliminar todos los bots.

Es aumentar progresivamente:

```text
attacker cost
```

y reducir:

```text
automation advantage
```

hasta que:

```text
Expected Cost
-------------
Expected Profit

```

deje de ser atractivo.

Las defensas pueden aumentar:

```text
time cost
compute cost
identity cost
device cost
operational complexity
capital cost
```

---

# 32. Posicionamiento conceptual

FairQueue puede describirse como:

> **Adaptive Risk-Weighted Virtual Waiting Room**

o:

> **Fair admission control for high-demand digital resources**

No tiene que limitarse exclusivamente a ticketing.

El mismo mecanismo puede utilizarse para:

- entradas;
- sneaker drops;
- collectibles;
- GPU drops;
- limited editions;
- reservas escasas;
- turnos gubernamentales;
- citas consulares;
- lanzamientos de productos;
- cualquier recurso digital con demanda extrema.

---

# 33. Visión

La primitive principal sería:

```text
M usuarios
+
N recursos escasos
+
capacidad limitada
+
señales de riesgo
+
asignación temporal
```

FairQueue decide:

```text
quién puede entrar
+
cuándo puede entrar
+
cuánta prioridad conserva
```

sin requerir modificaciones en el backend existente.

---

# 34. MVP recomendado

Primera versión:

```text
Dynamic Nginx module
+
shared memory
+
deterministic allocation
+
automatic waiting window
+
waiting room
+
retry penalty
+
same-device penalty
+
simple behavioral signals
+
status endpoint
```

Sin:

```text
Redis
database
ML
KYC
distributed cluster
complex graph analysis
```

La prioridad inicial debe ser:

> instalación simple, demo convincente y medición de adopción real.

Objetivo de distribución:

```text
install
configure one location
reload nginx
done
```

Ejemplo ideal:

```nginx
location /checkout {

    fairqueue on;

    fairqueue_capacity 500r/m;
    fairqueue_window auto;
    fairqueue_waiting_page /waiting.html;

    proxy_pass http://existing_backend;
}
```

El usuario conserva completamente su infraestructura existente.

FairQueue simplemente se convierte en una nueva primitive de control de tráfico dentro de Nginx.
