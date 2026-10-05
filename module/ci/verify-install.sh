#!/bin/sh
# Prueba install.sh dentro de un Nginx OFICIAL de stock (no uno que compilamos):
# instala el módulo en ese nginx y verifica que carga y gatea.
set -e

echo "== nginx de stock =="
nginx -v 2>&1
nginx -V 2>&1 | tr ' ' '\n' | grep -- --with-compat || echo "(sin --with-compat?)"

echo "== install.sh (compila contra ESTE nginx e instala el .so) =="
sh /module/install.sh
ls -l /etc/nginx/modules/ngx_http_fairqueue_module.so

echo "== config de prueba que CARGA el módulo en el nginx de stock =="
mkdir -p /tmp/www && echo ok-admitido > /tmp/www/open
cat > /tmp/fqtest.conf <<'EOF'
load_module modules/ngx_http_fairqueue_module.so;
error_log /tmp/err.log info;
pid /tmp/p.pid;
events {}
http {
  access_log off;
  fairqueue_zone zone=t:16m rate=500r/m;
  server {
    listen 8080;
    root /tmp/www;
    location = /waiting-room { return 200 "WR\n"; }
    location /open { fairqueue t; fairqueue_secret s; fairqueue_start 1;
                     fairqueue_scope o; }                 # pasado -> admite (sirve /tmp/www/open)
    location /q    { fairqueue t; fairqueue_secret s; fairqueue_start 4070908800;
                     fairqueue_scope q; fairqueue_waiting_uri /waiting-room; } # futuro -> 302
    location = /bad { fairqueue t; }                      # sin secreto (ver nota)
  }
}
EOF
# quitamos el location sin secreto para que -t pase (si no, fail-closed aborta: correcto)
sed -i '/location = \/bad/d' /tmp/fqtest.conf

echo "== nginx -t (debe cargar el módulo) =="
nginx -c /tmp/fqtest.conf -t

echo "== runtime =="
nginx -c /tmp/fqtest.conf
sleep 1
apk add --no-cache curl >/dev/null 2>&1 || true
echo -n "/open (admite) -> "; curl -s http://127.0.0.1:8080/open
echo -n "/q (encola)    -> "; curl -s -D- -o /dev/null http://127.0.0.1:8080/q | grep -i '^HTTP\|^location' | tr -d '\r'
nginx -c /tmp/fqtest.conf -s stop 2>/dev/null || true
echo "== INSTALABLE: OK =="
