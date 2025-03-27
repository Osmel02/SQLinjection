local http = require("socket.http")
local ltn12 = require("ltn12")

function detect_sqli(query)
    local response = {}
    local payload = '{"query":"' .. query:gsub('"', '\\"') .. '"}'
    
    local res, code = http.request{
        url = "http://127.0.0.1:5000/analyze",
        method = "POST",
        headers = {
            ["Content-Type"] = "application/json",
            ["Content-Length"] = #payload
        },
        source = ltn12.source.string(payload),
        sink = ltn12.sink.table(response)
    }
    
    if code == 200 then
        return string.match(table.concat(response), '"malicious":true')
    end
    return false
end