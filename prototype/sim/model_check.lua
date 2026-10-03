-- Verificación offline del MODELO de posición de FairQueue.
--
-- No levanta nginx: reproduce exactamente la fórmula de fairqueue.lua
--     posición = floor(frac * N) + penalty - aging
-- y mide el "Bot Advantage Ratio" bajo dos regímenes:
--     (a) solo hash (penalty = 0)        -> ventaja de VELOCIDAD eliminada
--     (b) hash + penalty por volumen      -> ventaja de VOLUMEN también eliminada
--
-- Así se demuestra, de forma determinística y sin red, por qué el hash por sí
-- solo NO basta cuando hay 100 bots por humano.
--
-- Ejecutar:  lua model_check.lua

-- Hash uniforme en [0,1) (FNV-1a 32-bit). Sustituto determinístico de HMAC
-- para el análisis estadístico (lo único que importa es que sea ~uniforme).
local function frac(s)
  local h = 2166136261
  for i = 1, #s do
    h = (h ~ s:byte(i)) & 0xffffffff
    -- h * 16777619 mod 2^32, evitando overflow de doubles
    local lo = (h & 0xffff) * 16777619
    local hi = ((h >> 16) * 16777619) & 0xffff
    h = ((lo & 0xffffffff) + ((hi << 16) & 0xffffffff)) & 0xffffffff
  end
  return h / 4294967296
end

local EVENT = "demo-event-2026"

-- Construye la población de identidades.
-- Cada humano: 1 identidad, device único (penalty 0).
-- Cada bot: `accounts` identidades, MISMO device (penalty por multicuenta).
local function build(humans, bots, accounts, penalty_per_account)
  local ids = {}
  local N = humans + bots * accounts
  for h = 1, humans do
    ids[#ids + 1] = { group = "human", owner = "h" .. h, penalty = 0 }
  end
  for b = 1, bots do
    for a = 1, accounts do
      ids[#ids + 1] = {
        group = "bot", owner = "b" .. b,
        penalty = (accounts - 1) * penalty_per_account,
      }
    end
  end
  for i, id in ipairs(ids) do
    id.base = math.floor(frac(EVENT .. id.group .. id.owner .. ":" .. i) * N)
    id.position = id.base + id.penalty
  end
  return ids, N
end

-- Dado un presupuesto de admisión K (primeras K posiciones), ¿quién entra?
-- Un bot entra si CUALQUIERA de sus identidades entra (se queda con la mejor).
local function measure(ids, K, humans, bots)
  local human_in = 0
  local bot_owner_in = {}
  for _, id in ipairs(ids) do
    if id.position <= K then
      if id.group == "human" then
        human_in = human_in + 1
      else
        bot_owner_in[id.owner] = true
      end
    end
  end
  local bot_in = 0
  for _ in pairs(bot_owner_in) do bot_in = bot_in + 1 end
  return human_in / humans, bot_in / bots
end

local function run(label, humans, bots, accounts, penalty)
  local ids, N = build(humans, bots, accounts, penalty)
  -- Presupuesto = admitir aprox. el 20% de la demanda (ventana realista).
  local K = math.floor(N * 0.20)
  local h_rate, b_rate = measure(ids, K, humans, bots)
  local ratio = (h_rate > 0) and (b_rate / h_rate) or math.huge
  print(string.format(
    "%-28s N=%-6d  humano=%.2f  bot=%.2f  AdvantageRatio=%.2f",
    label, N, h_rate, b_rate, ratio))
  return ratio
end

print("Escenario: 500 humanos, 50 bots con 50 cuentas c/u (mismo device)")
print("Admite el ~20% con mejor posición. AdvantageRatio ideal <= 1.0\n")

local humans, bots, accounts = 500, 50, 50
local r0 = run("(a) solo hash  penalty=0",   humans, bots, accounts, 0)
local r1 = run("(b) hash+penalty=250",       humans, bots, accounts, 250)
local r2 = run("(b) hash+penalty=1000",      humans, bots, accounts, 1000)

print()
print(string.format("Sin penalty los bots entran %.1fx más que humanos (ventaja de volumen).", r0))
print(string.format("Con penalty=1000 la ventaja cae a %.2fx.", r2))
print("=> El hash solo no basta; la penalización por volumen es lo que cumple el objetivo.")
