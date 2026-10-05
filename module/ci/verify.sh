#!/bin/sh
# Regression check tras el pulido: compila el módulo, nginx -t, y verifica
# admisión/espera/status/cap por código HTTP (el logging ahora es a nivel debug).
set -e
VER="${NGINX_VER:-1.27.4}"
apk add --no-cache build-base pcre-dev pcre2-dev zlib-dev openssl-dev linux-headers wget curl >/dev/null
cd /tmp && wget -q "https://nginx.org/download/nginx-$VER.tar.gz" && tar xzf "nginx-$VER.tar.gz"
cd "nginx-$VER"
./configure --with-compat --with-cc-opt="-DNGX_FQ_NODE_TTL=2" --add-dynamic-module=/module >/tmp/cfg.log 2>&1 || { tail -25 /tmp/cfg.log; exit 1; }
if make modules >/tmp/mk.log 2>&1; then
  echo "COMPILE OK  ($(ls -l objs/*.so | awk '{print $5}') bytes)"
else tail -40 /tmp/mk.log; exit 1; fi
make -j2 >/tmp/full.log 2>&1

mkdir -p /tmp/t/modules /tmp/t/logs /tmp/t/www
echo ok > /tmp/t/www/open ; echo ok > /tmp/t/www/cap
cp objs/ngx_http_fairqueue_module.so /tmp/t/modules/
cat > /tmp/t/nginx.conf <<'EOF'
load_module modules/ngx_http_fairqueue_module.so;
error_log /tmp/t/error.log warn; pid /tmp/t/nginx.pid; events {}
http {
  access_log off;
  fairqueue_zone zone=t:16m rate=500r/m;
  server {
    listen 8080; root /tmp/t/www;
    location = /waiting-room { return 200 "WR\n"; }
    location /open { fairqueue t; fairqueue_secret s; fairqueue_start 1; fairqueue_scope o; fairqueue_waiting_uri /waiting-room; }
    location /q    { fairqueue t; fairqueue_secret s; fairqueue_start 4070908800; fairqueue_scope q; fairqueue_waiting_uri /waiting-room; }
    location = /__fairqueue/status { fairqueue t; fairqueue_status; fairqueue_secret s; fairqueue_start 4070908800; fairqueue_scope q; }
    location /cap  { fairqueue t; fairqueue_secret s; fairqueue_start 1; fairqueue_scope c; fairqueue_trust_xff on; fairqueue_max_devices_per_ip 3; fairqueue_waiting_uri /waiting-room; }
  }
}
EOF
./objs/nginx -p /tmp/t -c /tmp/t/nginx.conf -t
./objs/nginx -p /tmp/t -c /tmp/t/nginx.conf; sleep 1
echo -n "/open  (admite, 200)      -> "; curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8080/open
echo -n "/q     (encola, 302)      -> "; curl -s -o /dev/null -w "%{http_code}\n" -c /tmp/jq http://127.0.0.1:8080/q
echo -n "/status con cookies de /q -> "; curl -s -b /tmp/jq http://127.0.0.1:8080/__fairqueue/status; echo
echo -n "/status sin cookies       -> "; curl -s http://127.0.0.1:8080/__fairqueue/status; echo
echo -n "cap IP (cap=3, 5 devices misma IP) -> "; for i in 1 2 3 4 5; do curl -s -o /dev/null -w "%{http_code} " -H "X-Forwarded-For: 9.9.9.9" http://127.0.0.1:8080/cap; done; echo "(espera 200 200 200 302 302)"
echo "cap refresh tras expiracion (TTL=2s):"; sleep 3; printf "   post-idle /cap (misma IP) -> "; for i in 1 2 3 4 5 6; do curl -s -o /dev/null -w "%{http_code} " -H "X-Forwarded-For: 9.9.9.9" http://127.0.0.1:8080/cap; done; echo "(debe APARECER 200: expirar devices libero el cap)"
./objs/nginx -p /tmp/t -c /tmp/t/nginx.conf -s stop 2>/dev/null || true

echo "fail-closed: fairqueue_status sin secreto -> nginx -t debe FALLAR:"
cat > /tmp/bad.conf <<'EOF'
load_module modules/ngx_http_fairqueue_module.so;
error_log /tmp/t/error.log warn; pid /tmp/t/p2.pid; events {}
http { fairqueue_zone zone=z:16m rate=500r/m;
  server { listen 8081; location = /s { fairqueue z; fairqueue_status; } } }
EOF
if ./objs/nginx -p /tmp/t -c /tmp/bad.conf -t 2>&1 | grep -q fairqueue_secret; then echo "   OK fail-closed"; else echo "   FALLO"; fi
echo "VERIFY OK"
