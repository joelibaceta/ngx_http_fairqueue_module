#!/bin/sh
# Verifica el packaging PPA construyéndolo como lo hace Launchpad
# (dpkg-buildpackage desde el árbol debian/) en Ubuntu, y luego apt-install.
set -e
docker run --rm -v ~/fairqueue/module:/src:ro ubuntu:24.04 bash -c '
  set -e; export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq nginx dpkg-dev debhelper build-essential \
      libpcre3-dev libpcre2-dev zlib1g-dev libssl-dev wget ca-certificates >/dev/null
  echo "== nginx de Ubuntu: $(nginx -v 2>&1) =="

  cp -r /src /tmp/build && cd /tmp/build
  rm -rf dist nginx-1* 2>/dev/null || true
  chmod +x debian/rules

  echo "== dpkg-buildpackage -b (rol Launchpad/CI) =="
  dpkg-buildpackage -b -us -uc 2>&1 | grep -iE "dpkg-deb: building|dpkg-buildpackage:|error" | tail -6
  echo "== .deb producido =="
  ls -l /tmp/nginx-module-fairqueue_*.deb

  echo "== apt install del .deb (rol USUARIO) =="
  apt-get install -y /tmp/nginx-module-fairqueue_*.deb >/tmp/ai.log 2>&1 && echo "apt install: OK" || { tail -8 /tmp/ai.log; exit 1; }
  echo "-- archivos instalados --"; dpkg -L nginx-module-fairqueue | grep -E "\.so$|\.conf$" | sed "s/^/   /"
  echo "-- $(dpkg -s nginx-module-fairqueue | grep ^Depends) --"

  echo "== nginx -t (modules-enabled auto-carga el módulo) =="
  grep -q "include /etc/nginx/modules-enabled" /etc/nginx/nginx.conf \
     && echo "   (nginx.conf incluye modules-enabled/*.conf -> auto-enabled)"
  nginx -t
  echo "PPA BUILD + APT INSTALL: OK"
'
