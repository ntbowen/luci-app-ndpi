-- LuCI controller for nDPI Deep Packet Inspection
-- Registers menu entries and dispatches pages

module("luci.controller.ndpi", package.seeall)

function index()
    -- Main menu entry under Services
    local e = entry({"admin", "services", "ndpi"},
        firstchild(), _("nDPI DPI Firewall"), 60)
    e.dependent = false
    e.acl_depends = { "luci-app-ndpi" }

    -- Dashboard (default landing page)
    entry({"admin", "services", "ndpi", "dashboard"},
        template("ndpi/dashboard"), _("Dashboard"), 10)

    -- Configuration page (UCI-based)
    entry({"admin", "services", "ndpi", "config"},
        cbi("ndpi/config"), _("Configuration"), 20)

    -- DPI & Traffic Analysis settings
    entry({"admin", "services", "ndpi", "dpi"},
        cbi("ndpi/dpi"), _("DPI Settings"), 30)

    -- Flow Collection settings
    entry({"admin", "services", "ndpi", "collector"},
        cbi("ndpi/collector"), _("Flow Collection"), 40)

    -- Security & Alerts
    entry({"admin", "services", "ndpi", "alerts"},
        cbi("ndpi/alerts"), _("Alerts & Security"), 50)

    -- Traffic Behavior Analysis
    entry({"admin", "services", "ndpi", "behavior"},
        cbi("ndpi/behavior"), _("Behavior Analysis"), 60)

    -- API endpoints for AJAX calls (accept both GET and POST)
    entry({"admin", "services", "ndpi", "api", "status"},
        call("api_status")).leaf = true
    entry({"admin", "services", "ndpi", "api", "protocols"},
        call("api_protocols")).leaf = true
    entry({"admin", "services", "ndpi", "api", "flows"},
        call("api_flows")).leaf = true
    entry({"admin", "services", "ndpi", "api", "alerts_data"},
        call("api_alerts")).leaf = true
    entry({"admin", "services", "ndpi", "api", "traffic"},
        call("api_traffic")).leaf = true
    entry({"admin", "services", "ndpi", "api", "start"},
        call("api_service_start")).leaf = true
    entry({"admin", "services", "ndpi", "api", "stop"},
        call("api_service_stop")).leaf = true
    entry({"admin", "services", "ndpi", "api", "restart"},
        call("api_service_restart")).leaf = true
    entry({"admin", "services", "ndpi", "api", "interface_stats"},
        call("api_interface_stats")).leaf = true
    entry({"admin", "services", "ndpi", "api", "debug"},
        call("api_debug")).leaf = true
end

-- ---------------------------------------------------------------
-- API handlers (return JSON for dashboard AJAX)
-- ---------------------------------------------------------------

local function json_response(data)
    local http = require "luci.http"
    http.prepare_content("application/json")
    http.write_json(data)
end

local function shell_exec(cmd)
    local handle = io.popen(cmd .. " 2>/dev/null")
    if not handle then return "" end
    local result = handle:read("*a")
    handle:close()
    return result or ""
end

-- ---------------------------------------------------------------
-- DPI Snapshot engine
-- ndpiReader only writes JSON at exit. We run a short-lived capture
-- instance in the background; when killed, it dumps accumulated DPI
-- results to a JSON file that the API reads on the next refresh.
-- ---------------------------------------------------------------
local SNAPSHOT_FILE = "/tmp/ndpi_snapshot.json"
local SNAPSHOT_INTERVAL = 20   -- min seconds between captures
local SNAPSHOT_DURATION = 5    -- seconds to capture before SIGINT

local function trigger_dpi_snapshot()
    local has_ndpi = shell_exec("which ndpiReader")
    if has_ndpi == "" then return end

    -- Only run while the main ndpiReader service is active
    local pids = shell_exec("pidof ndpiReader")
    local pid_count = 0
    for _ in pids:gmatch("%d+") do pid_count = pid_count + 1 end
    if pid_count < 1 then return end   -- service not running
    if pid_count > 1 then return end   -- snapshot already in progress

    -- Throttle: skip if triggered recently
    local ts_file = "/tmp/.ndpi_snap_ts"
    local mf = io.open(ts_file, "r")
    if mf then
        local ts = tonumber(mf:read("*l")) or 0
        mf:close()
        if (os.time() - ts) < SNAPSHOT_INTERVAL then return end
    end

    -- Record trigger time
    local wf = io.open(ts_file, "w")
    if wf then wf:write(tostring(os.time())); wf:close() end

    -- Resolve interface from UCI config
    local uci = require "luci.model.uci".cursor()
    local iface = uci:get("ndpi", "global", "interface") or "br-lan"
    -- Sanitize interface name
    iface = iface:gsub("[^%w%-_.]", "")

    -- Launch background snapshot:
    -- 1. Start ndpiReader capturing on the interface (with packet limit as safety)
    -- 2. Sleep SNAPSHOT_DURATION seconds
    -- 3. Send SIGINT (signal 2) — ndpiReader handles Ctrl-C to dump JSON on exit
    --    (SIGTERM does NOT trigger JSON output in most ndpiReader builds)
    -- 4. If still alive after grace period, force-kill
    os.execute(string.format(
        '(ndpiReader -i %s -K json -k %s -n 1000 2>/tmp/ndpi_snap_err.log & '
        .. 'P=$!; sleep %d; kill -2 $P 2>/dev/null; sleep 1; '
        .. 'kill -9 $P 2>/dev/null; wait $P 2>/dev/null'
        .. ') >/dev/null 2>&1 &',
        iface, SNAPSHOT_FILE, SNAPSHOT_DURATION
    ))
end

-- Read DPI protocol stats from the snapshot JSON
-- ndpiReader 6.0 writes NDJSON: one JSON object per line per flow.
-- Each flow has: src_ip, dest_ip, proto (L4), ndpi.proto (DPI name),
-- ndpi.category, ndpi.breed, etc.
local function read_snapshot_protocols()
    local jsonc = require "luci.jsonc"
    local f = io.open(SNAPSHOT_FILE, "r")
    if not f then return nil end

    local protocols = {}

    for line in f:lines() do
        line = line:match("^%s*(.-)%s*$")
        if line ~= "" and line:sub(1,1) == "{" then
            local ok, obj = pcall(jsonc.parse, line)
            if ok and type(obj) == "table" then
                -- ndpiReader 6.0 format: DPI protocol is in obj.ndpi.proto
                local ndpi_info = obj["ndpi"]
                local proto = nil
                local category = ""
                if type(ndpi_info) == "table" then
                    proto = ndpi_info["proto"]
                    category = ndpi_info["category"] or ""
                end
                -- Fallback field names for other ndpiReader versions
                if not proto or proto == "" then
                    proto = obj["detected.protocol.name"]
                        or obj["detected_protocol_name"]
                        or obj["ndpi_proto"]
                        or obj["app_protocol"]
                end
                if proto and proto ~= "" and proto ~= "Unknown" then
                    local byt  = tonumber(obj["bytes"] or 0) or 0
                    local pkts = tonumber(obj["packets"] or 0) or 0
                    local existing = protocols[proto]
                    if existing then
                        existing.count = existing.count + 1
                        existing.bytes = existing.bytes + byt
                        existing.packets = (existing.packets or 0) + pkts
                    else
                        protocols[proto] = {
                            count = 1,
                            bytes = byt,
                            packets = pkts,
                            category = category,
                        }
                    end
                end
            end
        end
    end
    f:close()

    if next(protocols) then return protocols end
    return nil
end

-- Read DPI-classified flows from the snapshot JSON (NDJSON format)
local function read_snapshot_flows()
    local jsonc = require "luci.jsonc"
    local f = io.open(SNAPSHOT_FILE, "r")
    if not f then return nil end

    local flows = {}
    local count = 0

    for line in f:lines() do
        if count >= 200 then break end
        line = line:match("^%s*(.-)%s*$")
        if line ~= "" and line:sub(1,1) == "{" then
            local ok, obj = pcall(jsonc.parse, line)
            if ok and type(obj) == "table" then
                -- ndpiReader 6.0: DPI protocol in obj.ndpi.proto
                local ndpi_info = obj["ndpi"]
                local proto = ""
                if type(ndpi_info) == "table" then
                    proto = ndpi_info["proto"] or ""
                end
                if proto == "" then
                    proto = obj["detected.protocol.name"]
                        or obj["detected_protocol_name"]
                        or obj["ndpi_proto"]
                        or obj["app_protocol"]
                        or ""
                end

                -- ndpiReader 6.0 uses "dest_ip" not "dst_ip"
                local src_ip   = obj["src_ip"]  or obj["src"]  or ""
                local dst_ip   = obj["dest_ip"] or obj["dst_ip"] or obj["dst"] or ""
                local src_port = obj["src_port"] or ""
                local dst_port = obj["dst_port"] or ""
                local byt  = tonumber(obj["bytes"] or 0) or 0
                local pkts = tonumber(obj["packets"] or 0) or 0

                if src_ip ~= "" or dst_ip ~= "" then
                    flows[#flows + 1] = {
                        src_ip   = src_ip,
                        dst_ip   = dst_ip,
                        protocol = proto,
                        src_port = tostring(src_port),
                        dst_port = tostring(dst_port),
                        bytes    = byt,
                        packets  = pkts,
                    }
                    count = count + 1
                end
            end
        end
    end
    f:close()

    if #flows > 0 then return flows end
    return nil
end

function api_status()
    -- pidof is reliable on BusyBox/OpenWrt; returns space-separated PIDs
    local pids = shell_exec("pidof ndpiReader")
    local pid = pids:match("(%d+)") or ""
    local running = pid ~= ""
    local mem_rss = 0
    local mem_virt = 0
    local uptime = 0

    if running then
        local status_file = "/proc/" .. pid .. "/status"
        local f = io.open(status_file, "r")
        if f then
            for line in f:lines() do
                local key, val = line:match("^(%S+):%s+(%d+)")
                if key == "VmRSS" then mem_rss = tonumber(val) or 0 end
                if key == "VmSize" then mem_virt = tonumber(val) or 0 end
            end
            f:close()
        end

        -- Calculate process uptime from /proc/<pid>/stat field 22 (starttime)
        -- and /proc/uptime. Works on BusyBox/OpenWrt where stat -c %Y fails.
        local proc_stat = shell_exec("cat /proc/" .. pid .. "/stat")
        local fields = {}
        for field in proc_stat:gmatch("%S+") do fields[#fields + 1] = field end
        local starttime_ticks = tonumber(fields[22]) or 0
        local clk_tck = tonumber(shell_exec("getconf CLK_TCK")) or 100
        local uptime_str = shell_exec("cat /proc/uptime")
        local sys_uptime = tonumber(uptime_str:match("^(%S+)")) or 0
        uptime = math.floor(sys_uptime - (starttime_ticks / clk_tck))
        if uptime < 0 then uptime = 0 end
    end

    -- System memory
    local meminfo = {}
    local mf = io.open("/proc/meminfo", "r")
    if mf then
        for line in mf:lines() do
            local key, val = line:match("^(%S+):%s+(%d+)")
            if key then meminfo[key] = tonumber(val) or 0 end
        end
        mf:close()
    end

    json_response({
        running = running,
        pid = running and pid or "N/A",
        memory_rss = mem_rss,
        memory_virtual = mem_virt,
        uptime = uptime,
        system_memory = {
            total = meminfo["MemTotal"] or 0,
            free = meminfo["MemFree"] or 0,
            available = meminfo["MemAvailable"] or 0,
            buffers = meminfo["Buffers"] or 0,
            cached = meminfo["Cached"] or 0,
        }
    })
end

function api_protocols()
    -- Trigger a background DPI snapshot capture (throttled internally)
    trigger_dpi_snapshot()

    local uci = require "luci.model.uci".cursor()
    local json_log = uci:get("ndpi", "global", "json_log") or "/tmp/ndpi_flows.json"
    local jsonc = require "luci.jsonc"

    local protocols = {}
    local source = "none"

    -- Method 0: DPI snapshot (short-lived ndpiReader capture with JSON dump)
    local snap_protos = read_snapshot_protocols()
    if snap_protos then
        protocols = snap_protos
        source = "dpi_snapshot"
    end

    -- Method 1: nDPI kernel module /proc/net/xt_ndpi/proto
    -- Real DPI protocol statistics from the kernel module (if loaded)
    if next(protocols) == nil then
    local proc_paths = {
        "/proc/net/xt_ndpi/proto",
        "/proc/net/xt_ndpi/protocols",
        "/sys/module/xt_ndpi/proto",
    }
    for _, path in ipairs(proc_paths) do
        local f = io.open(path, "r")
        if f then
            for line in f:lines() do
                -- Format: id proto_name packets bytes [flows]
                -- Or:     id  proto_name  packets  bytes
                -- Skip comment/header lines
                if not line:match("^#") and not line:match("^%s*$") then
                    local name, pkts, byt = line:match("^%s*%d+%s+(%S+)%s+(%d+)%s+(%d+)")
                    if name and name ~= "Unknown" then
                        local p = tonumber(pkts) or 0
                        local b = tonumber(byt) or 0
                        if p > 0 then
                            protocols[name] = { count = p, bytes = b }
                        end
                    end
                end
            end
            f:close()
            if next(protocols) ~= nil then
                source = "xt_ndpi"
                break
            end
        end
    end
    end -- close Method 1 guard

    -- Method 2: Try NDJSON from flow log
    if next(protocols) == nil then
        local f = io.open(json_log, "r")
        if f then
            for line in f:lines() do
                line = line:match("^%s*(.-)%s*$")
                if line ~= "" and line:sub(1,1) == "{" then
                    local ok, obj = pcall(jsonc.parse, line)
                    if ok and type(obj) == "table" then
                        local proto = obj["detected.protocol.name"]
                            or obj["detected_protocol_name"]
                            or obj["ndpi_proto"] or obj["proto"]
                            or obj["app_protocol"] or obj["protocol"]
                            or obj["detected_protocol"]
                        local byt = tonumber(obj["bytes"] or obj["flow.bytes"] or 0) or 0
                        if proto and proto ~= "" and proto ~= "Unknown" then
                            local existing = protocols[proto]
                            if existing then
                                existing.count = existing.count + 1
                                existing.bytes = existing.bytes + byt
                            else
                                protocols[proto] = { count = 1, bytes = byt }
                            end
                        end
                    end
                end
            end
            f:close()
            if next(protocols) ~= nil then source = "json_ndjson" end
        end
    end

    -- Method 3: Try single JSON document
    if next(protocols) == nil then
        local f2 = io.open(json_log, "r")
        if f2 then
            local content = f2:read("*a") or ""
            f2:close()
            if #content > 2 then
                local ok, data = pcall(jsonc.parse, content)
                if ok and type(data) == "table" then
                    local flows = data.flows or data
                    if type(flows) == "table" then
                        for _, fl in ipairs(flows) do
                            if type(fl) == "table" then
                                local proto = fl["detected.protocol.name"]
                                    or fl["detected_protocol_name"]
                                    or fl["ndpi_proto"] or fl["proto"]
                                    or fl["app_protocol"] or fl["protocol"]
                                    or fl["detected_protocol"]
                                local byt = tonumber(fl["bytes"] or 0) or 0
                                if proto and proto ~= "" and proto ~= "Unknown" then
                                    local existing = protocols[proto]
                                    if existing then
                                        existing.count = existing.count + 1
                                        existing.bytes = existing.bytes + byt
                                    else
                                        protocols[proto] = { count = 1, bytes = byt }
                                    end
                                end
                            end
                        end
                    end
                end
                if next(protocols) ~= nil then source = "json_single" end
            end
        end
    end

    -- Method 4: Parse ndpiReader stdout from syslog
    if next(protocols) == nil then
        local syslog = shell_exec("logread 2>/dev/null | grep -i ndpi | tail -500")
        if syslog and #syslog > 0 then
            -- ndpiReader logs: [proto: NN.NN/ProtoName]
            for proto in syslog:gmatch("%[proto:%s*[^/]*/([^%]]+)%]") do
                proto = proto:match("^%s*(.-)%s*$")
                if proto ~= "" and proto ~= "Unknown" then
                    local existing = protocols[proto]
                    if existing then
                        existing.count = existing.count + 1
                    else
                        protocols[proto] = { count = 1, bytes = 0 }
                    end
                end
            end
            -- Also try: "nDPI: detected X as ProtoName"
            if next(protocols) == nil then
                for proto in syslog:gmatch("detected%s+%S+%s+as%s+(%S+)") do
                    if proto ~= "Unknown" then
                        local existing = protocols[proto]
                        if existing then
                            existing.count = existing.count + 1
                        else
                            protocols[proto] = { count = 1, bytes = 0 }
                        end
                    end
                end
            end
            if next(protocols) ~= nil then source = "syslog" end
        end
    end

    -- Method 5: Fallback — conntrack L4 (last resort)
    if next(protocols) == nil then
        local ct = io.open("/proc/net/nf_conntrack", "r")
        if ct then
            for line in ct:lines() do
                local proto = line:match("^%S+%s+%S+%s+(%S+)")
                if proto then
                    local name = proto:upper()
                    local existing = protocols[name]
                    if existing then
                        existing.count = existing.count + 1
                    else
                        protocols[name] = { count = 1, bytes = 0 }
                    end
                end
            end
            ct:close()
            source = "conntrack"
        end
    end

    local result = {}
    for name, data in pairs(protocols) do
        result[#result + 1] = {
            protocol = name,
            count = data.count or 0,
            bytes = data.bytes or 0,
            packets = data.packets or 0,
            category = data.category or "",
        }
    end
    table.sort(result, function(a, b) return (a.count or 0) > (b.count or 0) end)

    json_response({ protocols = result, source = source })
end

function api_flows()
    -- Trigger a background DPI snapshot capture (throttled internally)
    trigger_dpi_snapshot()

    local uci = require "luci.model.uci".cursor()
    local json_log = uci:get("ndpi", "global", "json_log") or "/tmp/ndpi_flows.json"
    local jsonc = require "luci.jsonc"

    local flows = {}
    local source = "none"

    -- Method 0: DPI snapshot flows (real DPI-classified data)
    local snap_flows = read_snapshot_flows()
    if snap_flows then
        flows = snap_flows
        source = "dpi_snapshot"
    end

    -- Method 1: Try NDJSON (one JSON object per line)
    if #flows == 0 then
    local f = io.open(json_log, "r")
    if f then
        local count = 0
        for line in f:lines() do
            if count >= 200 then break end
            line = line:match("^%s*(.-)%s*$")
            if line ~= "" and line:sub(1,1) == "{" then
                local ok, obj = pcall(jsonc.parse, line)
                if ok and type(obj) == "table" then
                    flows[#flows + 1] = {
                        src_ip   = obj["src_ip"] or obj["src.ip"] or obj["src"] or "",
                        dst_ip   = obj["dst_ip"] or obj["dst.ip"] or obj["dst"] or "",
                        protocol = obj["detected.protocol.name"] or obj["ndpi_proto"]
                                   or obj["app_protocol"] or obj["protocol"]
                                   or obj["detected_protocol"] or "",
                        src_port = obj["src_port"] or obj["src.port"] or "",
                        dst_port = obj["dst_port"] or obj["dst.port"] or "",
                        bytes    = obj["bytes"] or obj["flow.bytes"] or 0,
                        packets  = obj["packets"] or obj["flow.packets"] or 0,
                    }
                    count = count + 1
                end
            end
        end
        f:close()
    end
    end -- close Method 1 guard

    -- Method 2: Try single JSON document
    if #flows == 0 then
        local f2 = io.open(json_log, "r")
        if f2 then
            local content = f2:read("*a") or ""
            f2:close()
            if #content > 2 then
                local ok, data = pcall(jsonc.parse, content)
                if ok and type(data) == "table" then
                    -- Could be { flows: [...] } or just [...]
                    local src = data.flows or data
                    if type(src) == "table" then
                        for i, fl in ipairs(src) do
                            if i > 200 then break end
                            if type(fl) == "table" then
                                flows[#flows + 1] = {
                                    src_ip   = fl["src_ip"] or fl["src.ip"] or fl["src"] or "",
                                    dst_ip   = fl["dst_ip"] or fl["dst.ip"] or fl["dst"] or "",
                                    protocol = fl["detected.protocol.name"] or fl["ndpi_proto"]
                                               or fl["app_protocol"] or fl["protocol"]
                                               or fl["detected_protocol"] or "",
                                    src_port = fl["src_port"] or fl["src.port"] or "",
                                    dst_port = fl["dst_port"] or fl["dst.port"] or "",
                                    bytes    = fl["bytes"] or fl["flow.bytes"] or 0,
                                    packets  = fl["packets"] or fl["flow.packets"] or 0,
                                }
                            end
                        end
                    end
                end
            end
        end
    end

    -- Method 3: Fallback — parse /proc/net/nf_conntrack for active flows
    if #flows == 0 then
        local ct = io.open("/proc/net/nf_conntrack", "r")
        if ct then
            local count = 0
            for line in ct:lines() do
                if count >= 200 then break end
                local proto = line:match("^%S+%s+%S+%s+(%S+)") or ""
                -- conntrack has two src/dst pairs (original + reply); take first
                local src_ip = line:match("src=(%S+)")
                local dst_ip = line:match("dst=(%S+)")
                local src_port = line:match("sport=(%d+)")
                local dst_port = line:match("dport=(%d+)")
                local bytes = line:match("bytes=(%d+)")
                local packets = line:match("packets=(%d+)")

                if src_ip and dst_ip then
                    flows[#flows + 1] = {
                        src_ip   = src_ip,
                        dst_ip   = dst_ip,
                        protocol = proto:upper(),
                        src_port = src_port or "",
                        dst_port = dst_port or "",
                        bytes    = tonumber(bytes) or 0,
                        packets  = tonumber(packets) or 0,
                    }
                    count = count + 1
                end
            end
            ct:close()
        end
    end

    if source == "none" then
        if #flows > 0 then source = "conntrack" end
    end
    json_response({ flows = flows, total = #flows, source = source })
end

function api_alerts()
    local uci = require "luci.model.uci".cursor()
    local alert_log = uci:get("ndpi", "alerts", "alert_log") or "/tmp/ndpi_alerts.log"

    local alerts = {}

    -- Read alert log file
    local f = io.open(alert_log, "r")
    if f then
        for line in f:lines() do
            alerts[#alerts + 1] = { message = line, source = "alert_log" }
        end
        f:close()
    end

    -- Read syslog entries
    local syslog = shell_exec("logread 2>/dev/null | grep -i ndpi | tail -50")
    for line in syslog:gmatch("[^\n]+") do
        alerts[#alerts + 1] = { message = line, source = "syslog" }
    end

    json_response({ alerts = alerts })
end

function api_interface_stats()
    local uci = require "luci.model.uci".cursor()
    local iface = uci:get("ndpi", "global", "interface") or "br-lan"

    local function read_stat(name)
        local path = "/sys/class/net/" .. iface .. "/statistics/" .. name
        local f = io.open(path, "r")
        if f then
            local val = f:read("*l")
            f:close()
            return tonumber(val) or 0
        end
        return 0
    end

    json_response({
        interface = iface,
        rx_bytes = read_stat("rx_bytes"),
        tx_bytes = read_stat("tx_bytes"),
        rx_packets = read_stat("rx_packets"),
        tx_packets = read_stat("tx_packets"),
        rx_errors = read_stat("rx_errors"),
        tx_errors = read_stat("tx_errors"),
    })
end

function api_traffic()
    local conns = {}
    local f = io.open("/proc/net/nf_conntrack", "r")
    if f then
        local count = 0
        for line in f:lines() do
            if count >= 100 then break end
            local proto = line:match("^%S+%s+%S+%s+(%S+)") or ""
            local src = line:match("src=(%S+)") or ""
            local dst = line:match("dst=(%S+)") or ""
            local sport = line:match("sport=(%d+)") or ""
            local dport = line:match("dport=(%d+)") or ""
            local state = line:match("%s(ESTABLISHED)%s")
                or line:match("%s(TIME_WAIT)%s")
                or line:match("%s(SYN_SENT)%s")
                or line:match("%s(SYN_RECV)%s")
                or line:match("%s(FIN_WAIT)%s")
                or line:match("%s(CLOSE_WAIT)%s")
                or line:match("%s(CLOSE)%s")
                or line:match("%s(LAST_ACK)%s")
                or line:match("%s(LISTEN)%s")
                or ""

            if src ~= "" and dst ~= "" then
                local label = proto:upper()
                if sport ~= "" then
                    label = label .. " " .. src .. ":" .. sport .. " → " .. dst .. ":" .. dport
                end
                conns[#conns + 1] = {
                    protocol = proto:upper(),
                    src = src .. (sport ~= "" and (":" .. sport) or ""),
                    dst = dst .. (dport ~= "" and (":" .. dport) or ""),
                    state = state,
                    raw = line,
                }
                count = count + 1
            end
        end
        f:close()
    end
    json_response({ connections = conns })
end

function api_service_start()
    os.execute("/etc/init.d/ndpi start")
    json_response({ result = "started" })
end

function api_service_stop()
    os.execute("/etc/init.d/ndpi stop >/dev/null 2>&1")
    -- Ensure the process is killed even if procd is slow
    os.execute("killall ndpiReader >/dev/null 2>&1")
    os.execute("sleep 1")
    -- Force-kill if still alive
    os.execute("killall -9 ndpiReader >/dev/null 2>&1")
    json_response({ result = "stopped" })
end

function api_service_restart()
    os.execute("/etc/init.d/ndpi restart")
    json_response({ result = "restarted" })
end

-- Debug endpoint: shows what data sources exist on this router
function api_debug()
    local uci = require "luci.model.uci".cursor()
    local json_log = uci:get("ndpi", "global", "json_log") or "/tmp/ndpi_flows.json"

    local info = {
        json_log_path = json_log,
        json_log_exists = false,
        json_log_size = 0,
        json_log_first_lines = {},
        proc_xt_ndpi_exists = false,
        proc_xt_ndpi_proto_sample = {},
        ndpi_kernel_module = shell_exec("lsmod 2>/dev/null | grep -i ndpi"),
        ndpiReader_cmdline = "",
        syslog_ndpi_sample = {},
        conntrack_count = 0,
    }

    -- Check JSON log file
    local f = io.open(json_log, "r")
    if f then
        info.json_log_exists = true
        local content = f:read("*a") or ""
        info.json_log_size = #content
        f:close()
        -- Get first 5 lines
        local i = 0
        for line in content:gmatch("[^\n]+") do
            i = i + 1
            if i > 5 then break end
            info.json_log_first_lines[i] = line:sub(1, 300)
        end
    end

    -- Check /proc/net/xt_ndpi/
    for _, path in ipairs({
        "/proc/net/xt_ndpi/proto",
        "/proc/net/xt_ndpi/protocols",
        "/proc/net/xt_ndpi/flows",
        "/proc/net/xt_ndpi/host_proto",
    }) do
        local pf = io.open(path, "r")
        if pf then
            info.proc_xt_ndpi_exists = true
            local i = 0
            for line in pf:lines() do
                i = i + 1
                if i > 10 then break end
                info.proc_xt_ndpi_proto_sample[#info.proc_xt_ndpi_proto_sample + 1] =
                    path .. ": " .. line:sub(1, 200)
            end
            pf:close()
        end
    end

    -- ndpiReader command line
    local pids = shell_exec("pidof ndpiReader")
    local pid = pids:match("(%d+)") or ""
    if pid ~= "" then
        info.ndpiReader_cmdline = shell_exec("cat /proc/" .. pid .. "/cmdline 2>/dev/null | tr '\\0' ' '")
    end

    -- Syslog sample
    local syslog = shell_exec("logread 2>/dev/null | grep -i ndpi | tail -10")
    local i = 0
    for line in syslog:gmatch("[^\n]+") do
        i = i + 1
        info.syslog_ndpi_sample[i] = line:sub(1, 300)
    end

    -- Conntrack count
    local ct_count = shell_exec("wc -l < /proc/net/nf_conntrack 2>/dev/null")
    info.conntrack_count = tonumber(ct_count:match("(%d+)")) or 0

    -- DPI Snapshot status
    info.snapshot_file = SNAPSHOT_FILE
    local sf = io.open(SNAPSHOT_FILE, "r")
    if sf then
        local sc = sf:read("*a") or ""
        sf:close()
        info.snapshot_exists = true
        info.snapshot_size = #sc
        -- Show first 500 chars for debugging
        info.snapshot_preview = sc:sub(1, 500)
    else
        info.snapshot_exists = false
        info.snapshot_size = 0
    end
    local tsf = io.open("/tmp/.ndpi_snap_ts", "r")
    if tsf then
        info.snapshot_last_trigger = tonumber(tsf:read("*l")) or 0
        tsf:close()
        info.snapshot_age = os.time() - info.snapshot_last_trigger
    end
    -- Snapshot error log (if any)
    local ef = io.open("/tmp/ndpi_snap_err.log", "r")
    if ef then
        info.snapshot_stderr = ef:read("*a") or ""
        ef:close()
    end
    -- ndpiReader help flags (first run only — helps debug which flags are supported)
    info.ndpiReader_version = shell_exec("ndpiReader -V 2>&1 | head -2")
    -- Count running ndpiReader processes
    info.ndpiReader_count = 0
    for _ in pids:gmatch("%d+") do info.ndpiReader_count = info.ndpiReader_count + 1 end

    json_response(info)
end
