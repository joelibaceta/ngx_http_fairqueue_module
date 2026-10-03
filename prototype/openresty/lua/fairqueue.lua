-- FairQueue — núcleo del algoritmo (prototipo OpenResty), endurecido tras red-team.
--
--   posición = max(0, floor(frac*N*(1+headroom)) + penalty - aging)
--   cursor   = rate * max(0, now - sale_start)
--   admitido <=> (now >= sale_start) AND posición <= cursor
--
-- Cambios de seguridad clave (ver analysis/REPORT.md §12):
--  * Nadie admitido antes de sale_start (el cursor=0 ya NO admite posición 0).
--  * Aging solo corre desde sale_start y está TOPADO (no reintroduce velocidad).
--  * Token de admisión ligado a event_id + scope (no replay entre colas).
--  * Anti-minado/DoS: cap de devices por IP; no se revela standing fino en registro.
--  * Volumen = max(cuentas/device, devices/IP); penalización fraccional de N.
--  * Comparación HMAC en tiempo constante; frac de 48 bits; cookies Secure opcional.

local cfg = require "config"
local str = require "resty.string"
local random = require "resty.random"
local bit = require "bit"  -- explícito (portabilidad; en OpenResty es global igual)

local _M = {}

local dict = ngx.shared[cfg.dict]
local TTL = 60 * 60 * 6 -- 6h

-- FAIL-CLOSED: con el secreto por defecto cualquiera forja cookies/tokens, así
-- que abortamos el arranque salvo que se pida explícitamente el modo demo.
if cfg.secret == "dev-secret-change-me" and not cfg.allow_default_secret then
  error("[fairqueue] FQ_SECRET no definido: setéalo en producción " ..
        "(o FQ_ALLOW_DEFAULT_SECRET=1 solo para la demo).")
end

-- ---------------------------------------------------------------------------
-- Config efectiva: defaults + overrides por location (modo experto)
-- ---------------------------------------------------------------------------
local PER_LOCATION = {
  "rate_per_sec", "start_epoch", "waiting_start_epoch", "waiting_uri",
  "token_ttl", "penalty_fraction", "aging_per_sec", "aging_cap_fraction",
  "window_headroom", "allocation", "scope", "max_devices_per_ip",
  "trust_xff", "cookie_secure", "risk_header", "risk_weight", "risk_fn",
}

local function merged(opts)
  local c = {}
  for _, k in ipairs(PER_LOCATION) do c[k] = cfg[k] end
  if opts then
    for _, k in ipairs(PER_LOCATION) do
      if opts[k] ~= nil then c[k] = opts[k] end
    end
  end
  if not c.rate_per_sec or c.rate_per_sec <= 0 then c.rate_per_sec = 500 / 60 end
  return c
end

-- ---------------------------------------------------------------------------
-- Hashing / firma
-- ---------------------------------------------------------------------------
local function hmac_hex(data)
  return str.to_hex(ngx.hmac_sha1(cfg.secret, data))
end

-- Comparación en tiempo constante (anti timing side-channel en la verificación).
local function ct_eq(a, b)
  if type(a) ~= "string" or type(b) ~= "string" then return false end
  if #a ~= #b then return false end
  local diff = 0
  for i = 1, #a do
    diff = bit.bor(diff, bit.bxor(a:byte(i), b:byte(i)))
  end
  return diff == 0
end

-- Fracción determinística en [0,1) a partir de 6 bytes (48 bits) del HMAC.
-- (48 bits evita colisiones de cumpleaños hasta ~2^24 participantes.)
local function frac(data)
  local b = ngx.hmac_sha1(cfg.secret, data)
  local hi = b:byte(1) * 65536 + b:byte(2) * 256 + b:byte(3)
  local lo = b:byte(4) * 65536 + b:byte(5) * 256 + b:byte(6)
  return (hi * 16777216 + lo) / 281474976710656
end

local function new_token_id()
  return str.to_hex(random.bytes(16))
end

-- ---------------------------------------------------------------------------
-- IP del cliente (origen del anti-minado/cap por IP)
-- ---------------------------------------------------------------------------
local function client_ip(c)
  if c.trust_xff then
    local xff = ngx.var.http_x_forwarded_for
    if xff and xff ~= "" then
      return (xff:match("^%s*([^,%s]+)")) or ngx.var.remote_addr
    end
  end
  return ngx.var.remote_addr or "0.0.0.0"
end

-- ---------------------------------------------------------------------------
-- Cookies firmadas
-- ---------------------------------------------------------------------------
local function get_cookie(name)
  local v = ngx.var["cookie_" .. name]
  if v == nil or v == "" then return nil end
  return v
end

local function sign(prefix, rid)
  return rid .. "." .. hmac_hex(prefix .. ":" .. rid)
end

local function verify(prefix, value)
  if not value then return nil end
  local rid, sig = value:match("^(%x+)%.(%x+)$")
  if not rid then return nil end
  if ct_eq(hmac_hex(prefix .. ":" .. rid), sig) then
    return rid
  end
  return nil
end

local function set_cookie(name, value, max_age, secure)
  local parts = { name .. "=" .. value, "Path=/", "SameSite=Lax", "HttpOnly" }
  if secure then parts[#parts + 1] = "Secure" end
  if max_age then parts[#parts + 1] = "Max-Age=" .. max_age end
  local existing = ngx.header["Set-Cookie"]
  local cookie = table.concat(parts, "; ")
  if existing == nil then
    ngx.header["Set-Cookie"] = cookie
  elseif type(existing) == "table" then
    existing[#existing + 1] = cookie
    ngx.header["Set-Cookie"] = existing
  else
    ngx.header["Set-Cookie"] = { existing, cookie }
  end
end

-- Clave de evento efectiva: event_id + scope + sale_start. Al incluir start_epoch,
-- el frac (orden) y el token ROTAN por drop: no se puede reusar una cartera de
-- devices "buenos" entre eventos, ni replayar tokens de un drop en otro, aunque
-- event_id/secret no cambien. scope separa colas distintas.
local function event_key(c)
  return cfg.event_id .. ":" .. c.scope .. ":" .. c.start_epoch
end

-- Token de admisión ligado a event_key + DEVICE + rid + exp.
-- Incluir devid evita que robar solo fq_adm (sin fq_dev) sirva, y que el token
-- se use desde otro device (anti replay entre colas, dispositivos Y drops).
local function adm_sig(c, rid, devid, exp)
  return hmac_hex("adm:" .. event_key(c) .. ":" .. devid .. ":" .. rid .. ":" .. exp)
end

local function issue_admission(c, rid, devid)
  local exp = ngx.time() + c.token_ttl
  set_cookie("fq_adm", rid .. "." .. exp .. "." .. adm_sig(c, rid, devid, exp),
    c.token_ttl, c.cookie_secure)
end

local function admission_valid(c, rid, devid)
  local v = get_cookie("fq_adm")
  if not v then return false end
  local trid, exp, sig = v:match("^(%x+)%.(%d+)%.(%x+)$")
  if not trid or trid ~= rid then return false end
  if tonumber(exp) < ngx.time() then return false end
  return ct_eq(adm_sig(c, trid, devid, exp), sig)
end

-- ---------------------------------------------------------------------------
-- Identidad + registro
-- ---------------------------------------------------------------------------
local function resolve_identity(c)
  local rid = verify("id", get_cookie("fq_id"))
  local devid = verify("dev", get_cookie("fq_dev"))

  if not devid then
    devid = new_token_id()
    set_cookie("fq_dev", sign("dev", devid), 60 * 60 * 24 * 30, c.cookie_secure)
  end
  if not rid then
    rid = new_token_id()
    set_cookie("fq_id", sign("id", rid), nil, c.cookie_secure)
  end
  return rid, devid
end

-- Registra participante (device) e identidad (cuenta). Idempotente.
--  * N = participantes (devices); first_seen anclado al device.
--  * Cap de devices NUEVOS por IP: acota inflación de N y minado de slots.
-- Devuelve (first_seen, rate_limited).
local function register(c, rid, devid, ip)
  local seen_dev = "seen:dev:" .. devid
  local first_seen = dict:get(seen_dev)
  if not first_seen then
    first_seen = ngx.time()
    -- add() atómico garantiza contar el device UNA sola vez (anti doble-conteo).
    if dict:add(seen_dev, first_seen, TTL) then
      -- Cap por IP ATÓMICO: incr primero y comparar el resultado (sin TOCTOU).
      local ipkey = "ipdev:" .. ip
      local ipn = dict:incr(ipkey, 1, 0, TTL)
      if ipn > c.max_devices_per_ip then
        dict:incr(ipkey, -1)   -- rollback
        dict:delete(seen_dev)  -- no contar este device
        return nil, true       -- rate-limited
      end
      local rank = dict:incr("N", 1, 0)
      dict:set("rank:" .. devid, rank, TTL)
    else
      first_seen = dict:get(seen_dev) or first_seen
    end
  end
  if dict:add("idseen:" .. rid, 1, TTL) then
    dict:incr("dev:" .. devid, 1, 0, TTL)
  end
  return first_seen, false
end

-- ---------------------------------------------------------------------------
-- Cálculo de posición / cursor
-- ---------------------------------------------------------------------------
local function evaluate(c, rid, devid, first_seen, ip)
  local now = ngx.time()
  local N = dict:get("N") or 1
  local dev_count = dict:get("dev:" .. devid) or 1
  local ip_devices = dict:get("ipdev:" .. ip) or 1
  local volume = math.max(dev_count, ip_devices) -- señal de volumen

  local span = N * (1 + c.window_headroom)

  local base
  if c.allocation == "fifo" then
    base = dict:get("rank:" .. devid) or N
  else
    base = math.floor(frac(event_key(c) .. ":" .. devid) * span)
  end

  -- Penalización = volumen interno (device/IP) + señal de riesgo EXTERNA enchufable.
  -- La señal externa suma posiciones (gradual), nunca bloquea; sin señal = 0.
  -- El header de riesgo SOLO se honra con trust_xff (mismo caveat: debe venir de
  -- un proxy de confianza que lo reescriba; en edge expuesto se ignora).
  local risk = 0
  if c.risk_fn then
    local ok, r = pcall(c.risk_fn)
    if ok and type(r) == "number" then risk = r end
  elseif c.trust_xff and c.risk_header and c.risk_header ~= "" then
    risk = tonumber(ngx.var["http_" .. c.risk_header:lower():gsub("-", "_")]) or 0
  end
  if risk ~= risk then risk = 0 end          -- NaN -> 0 (evita position NaN)
  if risk < 0 then risk = 0 elseif risk > 1 then risk = 1 end

  local penalty = math.floor((volume - 1) * c.penalty_fraction * N)
                + math.floor(risk * c.risk_weight * N)

  -- Aging: erosiona SOLO la penalización (anti-starvation / recuperación de falsos
  -- positivos), NUNCA la posición base del hash. Así un usuario honesto (penalty=0)
  -- no tiene término temporal => su posición es hash puro y la hora de llegada es
  -- 100% irrelevante (no hay ventaja por velocidad de registro). Topado al span.
  local waited = math.max(0, now - math.max(first_seen, c.start_epoch))
  local aging = math.min(
    math.floor(waited * c.aging_per_sec),
    math.floor(c.aging_cap_fraction * span))

  local position = base + math.max(0, penalty - aging)
  if position < 0 then position = 0 end

  local started = now >= c.start_epoch
  local cursor = c.rate_per_sec * math.max(0, now - c.start_epoch)
  -- Nadie admitido antes de sale_start (aunque position==0).
  local admitted = started and position <= cursor

  local reach = c.start_epoch + position / c.rate_per_sec
  local eta = admitted and 0 or math.max(0, math.ceil(reach - now))
  local waiting_now = math.max(0, N - math.floor(cursor))

  return {
    position = position,
    penalty = penalty,
    total = N,
    waiting_now = waiting_now,
    volume = volume,
    cursor = math.floor(cursor),
    admitted = admitted,
    eta_seconds = eta,
    phase = started and "sale" or "registration",
    sale_in = math.max(0, c.start_epoch - now),
    window_eta = math.ceil(waiting_now * (1 + c.window_headroom) / c.rate_per_sec),
  }
end

-- ---------------------------------------------------------------------------
-- API pública
-- ---------------------------------------------------------------------------
-- opts (opcional): overrides por location (modo experto). Ver PER_LOCATION.
function _M.gate(opts)
  local c = merged(opts)
  local rid, devid = resolve_identity(c)

  if admission_valid(c, rid, devid) then
    ngx.header["X-FairQueue-State"] = "admitted"
    return
  end

  if ngx.time() < c.waiting_start_epoch then
    ngx.header["X-FairQueue-State"] = "closed"
    return ngx.redirect(c.waiting_uri, ngx.HTTP_MOVED_TEMPORARILY)
  end

  local ip = client_ip(c)
  local first_seen, limited = register(c, rid, devid, ip)
  if limited then
    ngx.header["X-FairQueue-State"] = "rate_limited"
    return ngx.redirect(c.waiting_uri, ngx.HTTP_MOVED_TEMPORARILY)
  end

  local st = evaluate(c, rid, devid, first_seen, ip)
  if st.admitted then
    issue_admission(c, rid, devid)
    ngx.header["X-FairQueue-State"] = "admitted"
    return -- cae al proxy_pass
  end

  ngx.header["X-FairQueue-State"] = "waiting"
  return ngx.redirect(c.waiting_uri, ngx.HTTP_MOVED_TEMPORARILY)
end

-- SOLO-LECTURA: status() nunca registra, ni emite token, ni acuña cookies. El
-- encolado y la emisión de token ocurren únicamente en gate() (al navegar a la
-- ruta protegida). Así un <img src="/__fairqueue/status"> de un tercero NO puede
-- encolar víctimas ni inflar N (se cierra el CSRF de encolado).
function _M.status(opts)
  local c = merged(opts)
  ngx.header["Content-Type"] = "application/json"
  ngx.header["Cache-Control"] = "no-store"

  -- Lee identidad SIN acuñar. Si no entró por la ruta protegida aún, redirige.
  local rid = verify("id", get_cookie("fq_id"))
  local devid = verify("dev", get_cookie("fq_dev"))
  if not rid or not devid then
    ngx.say('{"state":"redirect","redirect":"/checkout"}')
    return
  end

  if admission_valid(c, rid, devid) then
    ngx.say('{"state":"admitted","redirect":"/checkout"}')
    return
  end

  local closed_in = c.waiting_start_epoch - ngx.time()
  if closed_in > 0 then
    ngx.say(string.format('{"state":"closed","opens_in":%d}', closed_in))
    return
  end

  -- Lectura pura del estado ya registrado (no crea device ni cuenta en N).
  local first_seen = dict:get("seen:dev:" .. devid)
  if not first_seen then
    ngx.say('{"state":"redirect","redirect":"/checkout"}')
    return
  end

  local st = evaluate(c, rid, devid, first_seen, client_ip(c))
  if st.admitted then
    ngx.say('{"state":"admitted","redirect":"/checkout"}')
    return
  end

  -- En REGISTRO no se revela standing fino (anti-minado de slots): solo que
  -- estás encolado y cuánto falta para la venta.
  if st.phase == "registration" then
    ngx.say(string.format(
      '{"state":"waiting","phase":"registration","total":%d,"sale_in":%d}',
      st.total, st.sale_in))
    return
  end

  -- En VENTA se revela posición/ETA para UX (ya no hay pre-selección posible).
  ngx.say(string.format(
    '{"state":"waiting","phase":"sale","position":%d,"total":%d,' ..
    '"waiting_now":%d,"cursor":%d,"eta_seconds":%d,"window_eta":%d}',
    st.position, st.total, st.waiting_now, st.cursor, st.eta_seconds, st.window_eta))
end

return _M
