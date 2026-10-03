#!/bin/sh
# Compila el módulo C y hace load-test (nginx -t). Pensado para correr dentro de
# un contenedor alpine con /module montado (ro).  Uso: sh /module/build.sh
set -e
VER="${NGINX_VER:-1.27.4}"

echo "== deps =="
apk add --no-cache build-base pcre-dev zlib-dev openssl-dev linux-headers wget >/dev/null

echo "== fuente nginx $VER =="
cd /tmp
wget -q "https://nginx.org/download/nginx-$VER.tar.gz"
tar xzf "nginx-$VER.tar.gz"
cd "nginx-$VER"

echo "== configure (--with-compat --add-dynamic-module) =="
./configure --with-compat --add-dynamic-module=/module >/tmp/configure.log 2>&1 \
  || { echo "CONFIGURE FALLÓ"; tail -20 /tmp/configure.log; exit 1; }

echo "== make modules =="
if make modules >/tmp/make.log 2>&1; then
  echo "COMPILE OK"; ls -la objs/*.so
else
  echo "COMPILE FALLÓ"; tail -40 /tmp/make.log; exit 1
fi

echo "== build nginx completo (para load-test) =="
make -j2 >/tmp/makefull.log 2>&1 || { echo "MAKE FALLÓ"; tail -20 /tmp/makefull.log; exit 1; }

echo "== load-test: nginx -t con load_module + fairqueue_zone + location =="
apk add --no-cache curl >/dev/null
mkdir -p /tmp/t/modules /tmp/t/html /tmp/t/logs
cp objs/ngx_http_fairqueue_module.so /tmp/t/modules/
echo ok > /tmp/t/html/open
cat > /tmp/t/nginx.conf <<'EOF'
load_module modules/ngx_http_fairqueue_module.so;
error_log /tmp/t/error.log info;
pid /tmp/t/nginx.pid;
events {}
http {
  access_log off;
  fairqueue_zone zone=tickets:16m rate=500r/m;
  server {
    listen 8099;
    root /tmp/t/html;
    location = /waiting-room { return 200 "WAITING-ROOM\n"; }

    # venta YA abierta (start pasado) -> admite
    location /open {
      fairqueue tickets; fairqueue_secret "s"; fairqueue_start 1;
      fairqueue_scope open; fairqueue_waiting_uri /waiting-room;
    }
    # venta en el FUTURO -> encola -> 302
    location /q {
      fairqueue tickets; fairqueue_secret "s"; fairqueue_start 4070908800;
      fairqueue_scope q; fairqueue_waiting_uri /waiting-room;
    }
    # endpoint de estado (read-only) con el MISMO scope/start/secret que /q
    location = /__fairqueue/status {
      fairqueue tickets; fairqueue_status;
      fairqueue_secret "s"; fairqueue_start 4070908800; fairqueue_scope q;
    }
    # cap por IP bajo (3) + trust_xff para probar rate-limit
    location /cap {
      fairqueue tickets; fairqueue_secret "s"; fairqueue_start 4070908800;
      fairqueue_scope cap; fairqueue_trust_xff on; fairqueue_max_devices_per_ip 3;
      fairqueue_waiting_uri /waiting-room;
    }
  }
}
EOF
./objs/nginx -p /tmp/t -c nginx.conf -t

echo "== runtime: gate + endpoint /status =="
./objs/nginx -p /tmp/t -c nginx.conf
sleep 1
echo "-- /open (pasado): ADMITE (200 + fq_adm) --"
curl -s -D - -o /dev/null -c /tmp/j1 http://127.0.0.1:8099/open | grep -iE '^(HTTP|set-cookie: fq_adm)'
echo "-- /q (futuro): ENCOLA (302) + registra identidad --"
curl -s -D - -o /dev/null -c /tmp/j2 http://127.0.0.1:8099/q | grep -iE '^(HTTP|location)'
echo "-- /status con la identidad de /q: JSON waiting/registration --"
curl -s -b /tmp/j2 http://127.0.0.1:8099/__fairqueue/status; echo
echo "-- /status SIN cookies: JSON redirect (read-only, no encola) --"
curl -s http://127.0.0.1:8099/__fairqueue/status; echo
echo "-- cap por IP (max 3, misma XFF 9.9.9.9): 5 devices nuevos -> 2 rate_limited --"
for i in 1 2 3 4 5; do curl -s -o /dev/null -H "X-Forwarded-For: 9.9.9.9" http://127.0.0.1:8099/cap; done
sleep 1
echo "   RATE_LIMITED en log: $(grep -c RATE_LIMITED /tmp/t/error.log)"
./objs/nginx -p /tmp/t -c nginx.conf -s stop 2>/dev/null || true

echo "== fail-closed: fairqueue sin fairqueue_secret -> nginx -t debe FALLAR =="
cat > /tmp/t/bad.conf <<'EOF'
load_module modules/ngx_http_fairqueue_module.so;
error_log /tmp/t/error.log info; pid /tmp/t/nginx.pid; events {}
http { fairqueue_zone zone=z:16m rate=500r/m;
  server { listen 8098; location /x { fairqueue z; } } }
EOF
if ./objs/nginx -p /tmp/t -c bad.conf -t 2>&1 | grep -q 'fairqueue_secret'; then
  echo "   OK: abortó por secreto faltante (fail-closed)"
else
  echo "   FALLO: no abortó sin secreto"
fi
echo "== OK TODO =="
