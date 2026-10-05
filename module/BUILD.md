# FairQueue — módulo C (build)

> **Estado: Fases 0–6 COMPLETAS** — compilado y verificado en runtime contra
> Nginx 1.27.4 (`--with-compat`). El módulo es un port funcional completo del
> prototipo Lua validado (`../prototype/`): identidad por cookies firmadas
> (HMAC-SHA1), shm (rbtree de devices + N activo con expiración LRU), admisión
> por `frac·span` vs cursor, token de admisión, redirect a waiting room, endpoint
> `/__fairqueue/status` (JSON read-only), cap por IP, hook de riesgo, y
> fail-closed del secreto.
>
> | Fase | Qué | Estado |
> |---|---|---|
> | 0–1 | directivas + conf + handler access | ✅ |
> | 2 | shm: rbtree devices + N activo + LRU | ✅ |
> | 3 | identidad (cookies firmadas) + HMAC + token | ✅ |
> | 4 | `evaluate()` → admitir / encolar (302) | ✅ |
> | 5 | `/__fairqueue/status` (JSON read-only) | ✅ |
> | 6 | cap por IP + riesgo + fail-closed secreto | ✅ |
> | 7 | ISO8601 en `fairqueue_start`, `.deb/.rpm`, CI matriz, `Test::Nginx` | ⬜ pendiente (packaging) |
>
> Verificación reproducible: `sh module/build.sh` dentro de un contenedor con
> `/module` montado (descarga el fuente de Nginx, `make modules`, `nginx -t`, y
> corre pruebas de admisión/espera/status/cap/fail-closed).

## Por qué el `.so` está atado a la versión de Nginx

Un módulo dinámico de Nginx es **ABI-compatible solo con el Nginx contra el que se
compiló** (misma versión y flags de `configure`). Por eso `apt install
nginx-module-fairqueue` implica compilar una matriz `(versión × arquitectura ×
distro)`. Compilar con `--with-compat` maximiza compatibilidad entre builds que
también usen `--with-compat` (los paquetes oficiales de nginx lo hacen).

## Build contra el código fuente de Nginx

```sh
# 1. Averigua la versión y flags del Nginx destino
nginx -V            # anota la versión y los configure arguments

# 2. Descarga ESA versión del fuente
VER=1.27.0
curl -O https://nginx.org/download/nginx-$VER.tar.gz
tar xzf nginx-$VER.tar.gz && cd nginx-$VER

# 3. Configura con --with-compat + los MISMOS flags del build destino, y el addon
./configure --with-compat \
    --add-dynamic-module=/ruta/a/ngx_http_fairqueue_module/module

# 4. Compila solo los módulos
make modules
# -> objs/ngx_http_fairqueue_module.so
```

## Instalar y cargar

```sh
sudo cp objs/ngx_http_fairqueue_module.so /etc/nginx/modules/
# en nginx.conf (contexto main, arriba del todo):
#   load_module modules/ngx_http_fairqueue_module.so;
sudo nginx -t && sudo systemctl reload nginx
```

## Config de ejemplo (Fase 0 ya la parsea toda)

```nginx
load_module modules/ngx_http_fairqueue_module.so;
http {
  server {
    location /checkout {
      fairqueue on;
      fairqueue_secret   "cambia-esto";
      fairqueue_rate     500r/m;
      fairqueue_start    1791050000;      # epoch (TODO: ISO8601 en Fase 1+)
      fairqueue_penalty  0.02;
      fairqueue_window_headroom 0.2;
      fairqueue_allocation hash;
      fairqueue_scope    checkout;
      fairqueue_waiting_uri /waiting-room;
      proxy_pass http://backend;
    }
  }
}
```
`nginx -t` debe validar; al pegarle a `/checkout` verás en el `error_log` la línea
`fairqueue: uri=... (Fase 0: pass-through)` y el request sigue normal al backend.

## Pendiente (fases siguientes)

| Fase | Qué falta | Dónde |
|---|---|---|
| 2 | zona shm: `ngx_shared_memory_add` + slab + rbtree de devices + N atómico + LRU | nuevo `init_zone` + `ngx_http_fairqueue_zone` |
| 3 | cookies (`r->headers_in.cookies`/`Set-Cookie`) + HMAC-SHA256 (OpenSSL) + `CRYPTO_memcmp` + token | handler |
| 4 | `evaluate()`: `base/penalty/aging/cursor` (port directo del Lua) | handler |
| 5 | redirect a waiting room (`ngx_http_internal_redirect`) + `/__fairqueue/status` (content handler, solo-lectura) | nuevo location handler |
| 6 | cap por IP (atómico) + `realip` para XFF de confianza + hook de riesgo | handler |
| 7 | parseo ISO8601 de `fairqueue_start`, `fairqueue_zone`, empaquetado `.deb/.rpm`, `Test::Nginx` | — |

Los tests del prototipo (`../prototype/sim/simulate.py`, `../prototype/analysis/
model.py`) se reutilizan contra el binario C: hablan HTTP y el comportamiento
esperado ya está caracterizado.
