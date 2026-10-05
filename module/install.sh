#!/bin/sh
# FairQueue — instalador del módulo dinámico de Nginx.
#
# Un .so de Nginx es ABI-compatible SOLO con el Nginx contra el que se compiló.
# Por eso este instalador detecta tu Nginx (versión + --with-compat), baja ESE
# fuente, compila el módulo y lo instala en tu modules-path. Funciona con
# cualquier Nginx (oficial de nginx.org, distro, etc.) que use --with-compat.
#
# Uso:
#   sudo sh install.sh              # detecta nginx del PATH, compila e instala
#   NGINX_BIN=/path/nginx sudo sh install.sh
#   sudo sh install.sh --enable     # además añade load_module a nginx.conf
#
# Variables: NGINX_BIN, NGINX_SRC (tarball/dir local opcional), MODULES_DIR.
set -e

SELF=$(cd "$(dirname "$0")" && pwd)
NGINX_BIN="${NGINX_BIN:-nginx}"
ENABLE=0
[ "$1" = "--enable" ] && ENABLE=1

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

command -v "$NGINX_BIN" >/dev/null 2>&1 || die "no encuentro nginx (define NGINX_BIN)"

VINFO=$("$NGINX_BIN" -V 2>&1)
VER=$(printf '%s' "$VINFO" | sed -n 's|.*nginx/\([0-9][0-9.]*\).*|\1|p' | head -1)
[ -n "$VER" ] || die "no pude detectar la versión de nginx"

case "$VINFO" in
  *--with-compat*) : ;;
  *) echo "AVISO: tu nginx no se compiló con --with-compat; el módulo podría no cargar." ;;
esac

# modules-path: del propio nginx -V, o un default sensato.
MODDIR="${MODULES_DIR:-$(printf '%s' "$VINFO" | sed -n 's|.*--modules-path=\([^ ]*\).*|\1|p' | head -1)}"
[ -n "$MODDIR" ] || MODDIR=/etc/nginx/modules
# prefix (para el load_module relativo y para hallar nginx.conf)
PREFIX=$(printf '%s' "$VINFO" | sed -n 's|.*--prefix=\([^ ]*\).*|\1|p' | head -1)
[ -n "$PREFIX" ] || PREFIX=/etc/nginx
CONF=$(printf '%s' "$VINFO" | sed -n 's|.*--conf-path=\([^ ]*\).*|\1|p' | head -1)
[ -n "$CONF" ] || CONF="$PREFIX/nginx.conf"

log "Nginx $VER | modules: $MODDIR | conf: $CONF"

# --- dependencias de compilación ---
install_deps() {
  if command -v apk >/dev/null 2>&1; then
    apk add --no-cache build-base pcre-dev pcre2-dev zlib-dev openssl-dev linux-headers wget >/dev/null
  elif command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq gcc make libpcre3-dev zlib1g-dev libssl-dev wget >/dev/null
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q gcc make pcre-devel zlib-devel openssl-devel wget >/dev/null
  else
    echo "AVISO: no pude instalar dependencias automáticamente; necesitas gcc/make/pcre/zlib/openssl."
  fi
}
log "Instalando dependencias de compilación…"
install_deps

# --- fuente de Nginx ---
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
if [ -n "$NGINX_SRC" ] && [ -d "$NGINX_SRC" ]; then
  SRC="$NGINX_SRC"
else
  log "Descargando fuente nginx-$VER…"
  wget -q "https://nginx.org/download/nginx-$VER.tar.gz" || die "no pude bajar el fuente"
  tar xzf "nginx-$VER.tar.gz"
  SRC="$WORK/nginx-$VER"
fi

# --- compilar el módulo ---
log "Compilando el módulo (--with-compat)…"
cd "$SRC"
./configure --with-compat --add-dynamic-module="$SELF" >/tmp/fq_configure.log 2>&1 \
  || { tail -20 /tmp/fq_configure.log; die "configure falló"; }
make modules >/tmp/fq_make.log 2>&1 \
  || { tail -30 /tmp/fq_make.log; die "make modules falló"; }

# --- instalar ---
mkdir -p "$MODDIR"
install -m 0644 objs/ngx_http_fairqueue_module.so "$MODDIR/ngx_http_fairqueue_module.so"
log "Instalado: $MODDIR/ngx_http_fairqueue_module.so"

LOADLINE="load_module modules/ngx_http_fairqueue_module.so;"
if [ "$ENABLE" = "1" ] && [ -f "$CONF" ]; then
  if grep -q 'ngx_http_fairqueue_module.so' "$CONF"; then
    log "load_module ya presente en $CONF"
  else
    cp "$CONF" "$CONF.fairqueue.bak"
    printf '%s\n%s\n' "$LOADLINE" "$(cat "$CONF")" > "$CONF"
    log "Añadido load_module a $CONF (backup: $CONF.fairqueue.bak)"
  fi
  "$NGINX_BIN" -t
fi

cat <<EOF

OK. Para activarlo, en el contexto 'main' de $CONF (arriba del todo):
  $LOADLINE

Y en la ruta a proteger:
  http {
    fairqueue_zone zone=tickets:32m rate=500r/m;
    server {
      location /checkout {
        fairqueue tickets;
        fairqueue_secret "CAMBIA-ESTO";
        fairqueue_start 1735740000;          # epoch de apertura (sale_start)
        fairqueue_waiting_uri /waiting-room;
        proxy_pass http://tu_backend;
      }
    }
  }
Luego:  nginx -t && nginx -s reload
EOF
