-- CBI model: nDPI General Configuration

local m, s, o

m = Map("ndpi", translate("nDPI General Configuration"),
    translate("Configure the core nDPI deep packet inspection service. "
    .. "nDPI identifies 450+ application protocols in real time, "
    .. "including encrypted TLS/QUIC traffic via fingerprinting."))

-- ---------------------------------------------------------------
-- Section: Global Settings
-- ---------------------------------------------------------------
s = m:section(NamedSection, "global", "ndpi",
    translate("Global Settings"))
s.addremove = false

o = s:option(Flag, "enabled", translate("Enable nDPI"),
    translate("Start the nDPI deep packet inspection engine."))
o.default = "1"
o.rmempty = false

o = s:option(ListValue, "interface", translate("Monitored Interface"),
    translate("Network interface to capture and analyze traffic on."))
-- Dynamically list interfaces
local uci = require("luci.model.uci").cursor()
local ifaces = {}
uci:foreach("network", "interface", function(sec)
    local ifname = sec[".name"]
    if ifname then
        ifaces[#ifaces + 1] = ifname
    end
end)
-- Also add physical interfaces
local handle = io.popen("ls /sys/class/net/ 2>/dev/null")
if handle then
    for iface in handle:lines() do
        if iface ~= "lo" then
            o:value(iface, iface)
        end
    end
    handle:close()
end
o.default = "br-lan"

o = s:option(ListValue, "log_level", translate("Log Verbosity"),
    translate("Controls the detail level of nDPI diagnostic logging."))
o:value("0", translate("Silent"))
o:value("1", translate("Normal"))
o:value("2", translate("Verbose"))
o:value("3", translate("Debug"))
o.default = "1"

o = s:option(Value, "json_log", translate("JSON Flow Log Path"),
    translate("File path where nDPI writes real-time flow data in JSON format. "
    .. "The dashboard reads from this file."))
o.default = "/tmp/ndpi_flows.json"
o.datatype = "string"

o = s:option(Value, "flow_max_packets", translate("Max Packets per Flow"),
    translate("Maximum number of packets to inspect per flow before "
    .. "committing a protocol verdict. Higher = more accurate, slower."))
o.default = "10"
o.datatype = "uinteger"

o = s:option(Flag, "enable_guess", translate("Enable Protocol Guessing"),
    translate("When nDPI cannot identify a protocol with certainty, "
    .. "use heuristics to make an educated guess."))
o.default = "1"

o = s:option(Flag, "decode_tunnels", translate("Decode Tunnels"),
    translate("Inspect traffic inside GRE, VXLAN, IP-in-IP, and other "
    .. "tunnel encapsulations to classify the inner payload."))
o.default = "1"

o = s:option(Flag, "track_payload", translate("Track Payload"),
    translate("Store a portion of the packet payload alongside flow data. "
    .. "Useful for debugging, but increases memory and CPU usage."))
o.default = "0"

return m
