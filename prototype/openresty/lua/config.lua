-- FairQueue — configuración del prototipo (defaults + modo experto por location).
--
-- Mapeo directiva del módulo C -> campo (los per-location se pueden sobreescribir
-- por location vía opts a gate()/status()):
--   fairqueue_secret <str>            -> secret           (zona, global)
--   fairqueue_rate 500r/m             -> rate_per_sec
--   fairqueue_start <iso8601>         -> start_epoch       (= sale_start)
--   fairqueue_waiting_start <iso8601> -> waiting_start_epoch
--   fairqueue_waiting_uri /waiting    -> waiting_uri
--   fairqueue_token_ttl 300           -> token_ttl
--   fairqueue_penalty 0.02            -> penalty_fraction  (fracción de N)
--   fairqueue_aging 0.5               -> aging_per_sec
--   fairqueue_aging_cap 0.5           -> aging_cap_fraction (tope = fracción del span)
--   fairqueue_window_headroom 0.2     -> window_headroom
--   fairqueue_allocation hash         -> allocation (hash | fifo)
--   fairqueue_scope <str>             -> scope  (liga el token a esta cola)
--   fairqueue_risk_header X-Risk-Score -> risk_header (detección enchufable)
--   fairqueue_risk_weight 0.5         -> risk_weight
--   fairqueue_max_devices_per_ip 64   -> max_devices_per_ip
--   fairqueue_trust_xff off           -> trust_xff
--   fairqueue_cookie_secure on        -> cookie_secure

local M = {}

-- ---- Zona (global) ----
M.secret = os.getenv("FQ_SECRET") or "dev-secret-change-me"
M.event_id = os.getenv("FQ_EVENT_ID") or "demo-event-2026"
M.dict = "fq"

-- Falla temprano si el secreto es el default inseguro y no estamos en modo demo.
M.allow_default_secret = (os.getenv("FQ_ALLOW_DEFAULT_SECRET") == "1")

-- ---- Per-location (overridables) ----
M.rate_per_sec = tonumber(os.getenv("FQ_RATE_PER_SEC")) or (500 / 60)
if not M.rate_per_sec or M.rate_per_sec <= 0 then M.rate_per_sec = 500 / 60 end

M.start_epoch = tonumber(os.getenv("FQ_START_EPOCH")) or os.time()

-- Apertura del registro (encolado). Antes de esto no se encola a nadie; entre
-- waiting_start y start el cursor está en 0 (se forma la cola). 0 => siempre abierto.
M.waiting_start_epoch = tonumber(os.getenv("FQ_WAITING_START")) or 0

M.waiting_uri = os.getenv("FQ_WAITING_URI") or "/waiting-room"
M.token_ttl = tonumber(os.getenv("FQ_TOKEN_TTL")) or 300

-- Penalización por cuenta/identidad extra, como FRACCIÓN de N (invariante al
-- volumen; ver analysis/REPORT.md §5). Volumen = max(cuentas por device,
-- devices por IP). p* ≈ ρ_escasa / k_objetivo (típico 0.01–0.03).
M.penalty_fraction = tonumber(os.getenv("FQ_PENALTY_FRACTION")) or 0.02

-- Aging: posiciones recuperadas por segundo ESPERANDO (solo cuenta desde
-- sale_start, nunca durante el registro) y TOPADO a aging_cap_fraction del span
-- para que no pueda voltear el orden del hash (anti-starvation, no carrera).
M.aging_per_sec = tonumber(os.getenv("FQ_AGING_PER_SEC")) or 0.5
-- Tope del aging como fracción del span. Bajo a propósito: el aging es solo
-- anti-starvation, NO debe permitir saltar gran parte de la cola por esperar.
M.aging_cap_fraction = tonumber(os.getenv("FQ_AGING_CAP_FRACTION")) or 0.1

M.window_headroom = tonumber(os.getenv("FQ_WINDOW_HEADROOM")) or 0.2
M.allocation = os.getenv("FQ_ALLOCATION") or "hash"

-- Scope: liga el token de admisión a esta cola (evita replay entre colas).
M.scope = os.getenv("FQ_SCOPE") or "default"

-- DETECCIÓN ENCHUFABLE (señal de riesgo externa). El integrador aporta un score
-- 0..1 desde un upstream de confianza (WAF/CDN/su propia lógica) y FairQueue lo
-- traduce a PENALIZACIÓN (posiciones), nunca a bloqueo: falla seguro (sin señal
-- = lotería pura) y es gradual (tolera falsos positivos). Debe venir de origen
-- de confianza (mismo caveat que trust_xff): un cliente solo puede bajar su
-- propio score al baseline, jamás subir el de otro. Vía header (abajo) o, en modo
-- experto, un hook Lua `risk_fn` por location que devuelva 0..1.
M.risk_header = os.getenv("FQ_RISK_HEADER") or ""            -- p.ej. "X-Risk-Score"; "" = off
M.risk_weight = tonumber(os.getenv("FQ_RISK_WEIGHT")) or 0.5 -- score 1.0 => +0.5*N posiciones

-- Anti-minado/DoS: nº máximo de devices NUEVOS contados por IP. Acota la
-- inflación de N y el minado online de slots (hay que pagar IPs, no cookies).
M.max_devices_per_ip = tonumber(os.getenv("FQ_MAX_DEVICES_PER_IP")) or 64

-- Origen de la IP del cliente. trust_xff solo debe activarse DETRÁS de un proxy
-- de confianza que setee X-Forwarded-For; en un edge expuesto permitiría forjar
-- la IP y evadir el cap. Default: usar la IP de conexión (remote_addr).
M.trust_xff = (os.getenv("FQ_TRUST_XFF") == "1")

-- Secure en cookies. Debe estar ON en producción (HTTPS). El prototipo corre
-- sobre HTTP, así que default OFF para que la demo funcione.
M.cookie_secure = (os.getenv("FQ_COOKIE_SECURE") == "1")

return M
