#!/bin/sh
# FairQueue invariant tests — the core principles of the design, as black-box
# assertions against a running nginx. Any contribution that breaks a principle
# fails here, regardless of how the C was changed. Exit non-zero on any failure.
#
# Each logical participant is given its own simulated address via
# X-Forwarded-For (trust_xff on) so the per-IP volume signal of one case never
# bleeds into another; the per-IP cap case deliberately shares one address.
#
# Run (inside a container with the module mounted at /module):
#   docker run --rm -v "$PWD":/module alpine:3.20 sh /module/ci/invariants.sh
set -e
VER="${NGINX_VER:-1.27.4}"

apk add --no-cache build-base pcre-dev pcre2-dev zlib-dev openssl-dev \
    linux-headers wget curl >/dev/null
cd /tmp && wget -q "https://nginx.org/download/nginx-$VER.tar.gz" \
    && tar xzf "nginx-$VER.tar.gz"
cd "nginx-$VER"
./configure --with-compat --add-dynamic-module=/module >/tmp/cfg.log 2>&1 \
    || { echo "configure failed"; tail -20 /tmp/cfg.log; exit 1; }
make modules >/tmp/mk.log 2>&1 || { echo "build failed"; tail -30 /tmp/mk.log; exit 1; }
make -j2 >/tmp/full.log 2>&1
NGX="$PWD/objs/nginx"

mkdir -p /tmp/t/modules /tmp/t/logs /tmp/t/www
cp objs/ngx_http_fairqueue_module.so /tmp/t/modules/
for f in future scarce cap t-a open; do echo ok > "/tmp/t/www/$f"; done

cat > /tmp/t/nginx.conf <<'EOF'
load_module modules/ngx_http_fairqueue_module.so;
error_log /tmp/t/error.log crit; pid /tmp/t/nginx.pid; events {}
http {
  access_log off;
  fairqueue_zone zone=t:16m rate=500r/m;
  server {
    listen 8080; root /tmp/t/www;
    location = /waiting-room { return 200 "WR\n"; }

    location /future { fairqueue t; fairqueue_secret s; fairqueue_start 4070908800; fairqueue_scope fut; fairqueue_trust_xff on; fairqueue_waiting_uri /waiting-room; }
    location = /future/status { fairqueue t; fairqueue_status; fairqueue_secret s; fairqueue_start 4070908800; fairqueue_scope fut; fairqueue_trust_xff on; }

    location /scarce { fairqueue t; fairqueue_secret s; fairqueue_start 1; fairqueue_rate 1r/h; fairqueue_scope scar; fairqueue_trust_xff on; fairqueue_waiting_uri /waiting-room; }
    location = /scarce/status { fairqueue t; fairqueue_status; fairqueue_secret s; fairqueue_start 1; fairqueue_rate 1r/h; fairqueue_scope scar; fairqueue_trust_xff on; }

    location /open { fairqueue t; fairqueue_secret s; fairqueue_start __NOW__; fairqueue_rate 5r/s; fairqueue_scope open; fairqueue_trust_xff on; fairqueue_waiting_uri /waiting-room; }

    location /cap { fairqueue t; fairqueue_secret s; fairqueue_start 1; fairqueue_scope cap; fairqueue_trust_xff on; fairqueue_max_devices_per_ip 3; fairqueue_waiting_uri /waiting-room; }

    location /t-a { fairqueue t; fairqueue_secret s; fairqueue_start 1; fairqueue_scope a; fairqueue_trust_xff on; fairqueue_waiting_uri /waiting-room; }
    location /t-b { fairqueue t; fairqueue_secret s; fairqueue_start 4070908800; fairqueue_scope b; fairqueue_trust_xff on; fairqueue_waiting_uri /waiting-room; }
  }
}
EOF
sed -i "s/__NOW__/$(date +%s)/" /tmp/t/nginx.conf

"$NGX" -p /tmp/t -c nginx.conf -t >/dev/null 2>&1 || { echo "nginx -t failed"; "$NGX" -p /tmp/t -c nginx.conf -t; exit 1; }
"$NGX" -p /tmp/t -c nginx.conf
sleep 1

B=http://127.0.0.1:8080
PASS=0; FAIL=0
ok(){ echo "  PASS  $1"; PASS=$((PASS+1)); }
no(){ echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
# code URI XFF [extra curl args...]
code(){ u=$1; xff=$2; shift 2; curl -s -o /dev/null -w "%{http_code}" -H "X-Forwarded-For: $xff" "$@" "$u"; }
get(){  u=$1; xff=$2; shift 2; curl -s -H "X-Forwarded-For: $xff" "$@" "$u"; }
jpos(){ grep -o '"position":[0-9]*' | head -1; }
jtot(){ grep -o '"total":[0-9]*' | head -1; }

echo "== FairQueue invariants =="

# P1 — no admission before sale_start (each request its own IP)
a=0; for i in $(seq 1 10); do [ "$(code $B/future 10.1.0.$i)" = 200 ] && a=$((a+1)); done
[ "$a" -eq 0 ] && ok "P1 nobody admitted before sale_start" || no "P1 $a/10 admitted before sale"

# P1b — registration withholds the fine-grained position
get $B/future 10.2.0.1 -c /tmp/jf >/dev/null
jf=$(get $B/future/status 10.2.0.1 -b /tmp/jf)
echo "$jf" | grep -q '"phase":"registration"' && ! echo "$jf" | grep -q '"position"' \
  && ok "P1b registration hides standing" || no "P1b leaked standing: $jf"

# grow the population (distinct IPs) so scarce positions are meaningful
for i in $(seq 1 30); do get $B/scarce 10.5.0.$i >/dev/null; done

# P2 — slot stable across rapid polls (speed does not change your place)
get $B/scarce 10.6.0.1 -c /tmp/js >/dev/null
p1=$(get $B/scarce/status 10.6.0.1 -b /tmp/js | jpos)
get $B/scarce/status 10.6.0.1 -b /tmp/js >/dev/null
p2=$(get $B/scarce/status 10.6.0.1 -b /tmp/js | jpos)
[ "$p1" = "$p2" ] && ok "P2 slot stable across polls (speed irrelevant)" \
  || no "P2 position changed: '$p1' vs '$p2'"

# P2b — slot frozen to the device: clearing fq_id (keeping fq_dev) does not re-roll
grep -v fq_id /tmp/js > /tmp/js2
get $B/scarce 10.6.0.1 -b /tmp/js2 -c /tmp/js2 >/dev/null
p3=$(get $B/scarce/status 10.6.0.1 -b /tmp/js2 | jpos)
[ "$p3" = "$p1" ] && ok "P2b slot frozen to device (no re-roll via F5/clear-id)" \
  || no "P2b re-roll changed slot: '$p1' -> '$p3'"

# P3 — admission bounded by rate (distinct IPs, so only the rate gates)
adm=0; for i in $(seq 1 60); do [ "$(code $B/open 10.7.0.$i)" = 200 ] && adm=$((adm+1)); done
{ [ "$adm" -ge 1 ] && [ "$adm" -lt 60 ]; } \
  && ok "P3 admission bounded by rate ($adm/60 in the window)" \
  || no "P3 not bounded: $adm/60"

# P4 — per-IP device cap (one shared IP, on purpose)
a=0; r=0; for i in $(seq 1 5); do c=$(code $B/cap 7.7.7.7); \
  [ "$c" = 200 ] && a=$((a+1)); [ "$c" = 302 ] && r=$((r+1)); done
{ [ "$a" -le 3 ] && [ "$r" -ge 2 ]; } \
  && ok "P4 per-IP cap holds ($a admitted, $r capped of 5)" \
  || no "P4 cap breached: $a admitted, $r capped"

# P6 — forgery rejected: a cookie with a bad signature is re-minted, not trusted
h=$(curl -s -D - -o /dev/null -H "X-Forwarded-For: 10.8.0.1" -H "Cookie: fq_id=aaaaaaaa.0000000000000000000000000000000000000000; fq_dev=bbbbbbbb.0000000000000000000000000000000000000000" $B/scarce)
echo "$h" | grep -qi '^set-cookie: fq_id' \
  && ok "P6 forged cookie rejected (re-minted)" || no "P6 forged cookie accepted"

# P7 — admission token is scoped to its queue (same user/IP for both calls)
get $B/t-a 10.9.0.1 -c /tmp/jta >/dev/null         # admitted here -> fq_adm (scope a)
ca=$(code $B/t-a 10.9.0.1 -b /tmp/jta)              # honored at its own scope
cb=$(code $B/t-b 10.9.0.1 -b /tmp/jta)              # not honored at another scope
{ [ "$ca" = 200 ] && [ "$cb" = 302 ]; } \
  && ok "P7 token scoped to its queue (A=$ca, B=$cb)" \
  || no "P7 token leaked across scope (A=$ca, B=$cb)"

# P8 — the status endpoint is read-only (never enqueues)
get $B/scarce 10.10.0.1 -c /tmp/jn >/dev/null
n0=$(get $B/scarce/status 10.10.0.1 -b /tmp/jn | jtot)
for i in $(seq 1 10); do get $B/scarce/status 10.11.0.$i >/dev/null; done
n1=$(get $B/scarce/status 10.10.0.1 -b /tmp/jn | jtot)
[ "$n0" = "$n1" ] && ok "P8 status is read-only (N stable: ${n0:-n/a})" \
  || no "P8 status enqueued: $n0 -> $n1"

"$NGX" -p /tmp/t -c nginx.conf -s stop 2>/dev/null || true

# P5 — fail-closed secret (config-time)
cat > /tmp/bad.conf <<'EOF'
load_module modules/ngx_http_fairqueue_module.so;
error_log /tmp/t/error.log crit; pid /tmp/t/p2.pid; events {}
http { fairqueue_zone zone=z:16m rate=500r/m;
  server { listen 8081; location = /s { fairqueue z; fairqueue_status; } } }
EOF
"$NGX" -p /tmp/t -c /tmp/bad.conf -t 2>&1 | grep -q fairqueue_secret \
  && ok "P5 fail-closed: refuses to start without a secret" \
  || no "P5 started without a secret"

echo "== $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ] || exit 1
