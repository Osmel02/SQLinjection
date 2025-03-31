local http = require("socket.http")
local ltn12 = require("ltn12")
local json = require("json")

-- Configuración del endpoint Flask
local FLASK_ENDPOINT = "http://localhost:5000/analyze"
local THRESHOLD = 0.85  -- Umbral de probabilidad para bloquear

-- Función para enviar datos a Flask
function send_to_flask(data)
    local response_body = {}
    local payload = json.encode(data)
    
    local res, code, headers = http.request{
        url = FLASK_ENDPOINT,
        method = "POST",
        headers = {
            ["Content-Type"] = "application/json",
            ["Content-Length"] = payload:len()
        },
        source = ltn12.source.string(payload),
        sink = ltn12.sink.table(response_body),
        timeout = 1  -- 1 segundo de timeout
    }
    
    if code == 200 then
        return json.decode(table.concat(response_body))
    else
        m.log(1, "Error al conectar con Flask. Código: "..tostring(code))
        return nil
    end
end

-- Función principal de inspección
function inspect_request()
    -- Solo analizar métodos que pueden contener SQLi
    if not (m.getvar("REQUEST_METHOD") == "POST" or m.getvar("REQUEST_METHOD") == "GET") then
        return false
    end

    -- Obtener todos los parámetros (GET y POST)
    local params = {}
    local args_get = m.getvars("ARGS_GET", {"none"})
    local args_post = m.getvars("ARGS_POST", {"none"})
    
    -- Combinar parámetros
    for _, v in ipairs(args_get) do table.insert(params, v) end
    for _, v in ipairs(args_post) do table.insert(params, v) end
    
    -- Filtrar parámetros con caracteres sospechosos
    local suspicious_params = {}
    for _, param in ipairs(params) do
        local name = param["name"]
        local value = param["value"]
        
        -- Detectar caracteres comúnmente usados en SQLi
        if value:match("['\"\\;%-%-]") or value:match("%sUNION%s") then
            table.insert(suspicious_params, {
                name = name,
                value = value,
                type = param["type"]
            })
        end
    end
    
    -- Si no hay parámetros sospechosos, permitir
    if #suspicious_params == 0 then
        return false
    end
    
    -- Preparar datos para Flask
    local request_data = {
        http_method = m.getvar("REQUEST_METHOD"),
        uri = m.getvar("REQUEST_URI"),
        headers = {
            user_agent = m.getvar("REQUEST_HEADERS:User-Agent"),
            referer = m.getvar("REQUEST_HEADERS:Referer")
        },
        suspicious_params = suspicious_params,
        client_ip = m.getvar("REMOTE_ADDR")
    }
    
    -- Enviar a Flask para análisis
    local flask_response = send_to_flask(request_data)
    
    if not flask_response then
        m.log(3, "Fallo al analizar con Flask. Acción por defecto: bloquear")
        return true  -- Bloquear por defecto si falla el análisis
    end
    
    -- Loggear resultado del análisis
    m.log(4, "Resultado análisis Flask: "..json.encode(flask_response))
    
    -- Tomar acción basada en la respuesta
    if flask_response.is_malicious and flask_response.probability >= THRESHOLD then
        -- Bloquear la solicitud
        m.log(3, "Bloqueando solicitud SQLi. Probabilidad: "..flask_response.probability)
        
        -- Opcional: Añadir detalles al log
        if flask_response.details then
            m.setvar("tx.sql_injection_details", flask_response.details)
        end
        
        return true  -- Bloquear
    end
    
    return false  -- Permitir
end

-- Función de inicialización (requerida por ModSecurity)
function init()
    m.log(4, "Iniciado script de detección SQLi con Flask")
    return nil
end