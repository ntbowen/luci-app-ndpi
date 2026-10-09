-- CBI model: Flow Collection Settings

local m, s, o

m = Map("ndpi", translate("Flow Collection"),
    translate("Configure ingestion of flow records from external sources. "
    .. "nDPI can receive NetFlow (v5/v9), sFlow, and IPFIX from routers, "
    .. "switches, and software agents like nProbe, enabling visibility "
    .. "across your entire network — not just the local router."))

-- ---------------------------------------------------------------
-- Section: General Collector Settings
-- ---------------------------------------------------------------
s = m:section(NamedSection, "collector", "flow_collection",
    translate("Flow Collector"))
s.addremove = false

o = s:option(Flag, "enabled", translate("Enable Flow Collector"),
    translate("Start listening for incoming flow records. "
    .. "You must enable at least one protocol below (NetFlow, sFlow, or IPFIX)."))
o.default = "0"

o = s:option(Value, "collector_interface", translate("Listening Address"),
    translate("IP address to bind the collector to. Use 0.0.0.0 to listen "
    .. "on all interfaces, or a specific IP for tighter control."))
o.default = "0.0.0.0"
o.datatype = "ipaddr"

-- ---------------------------------------------------------------
-- Section: NetFlow
-- ---------------------------------------------------------------
s = m:section(NamedSection, "collector", "flow_collection",
    translate("NetFlow"),
    translate("NetFlow is Cisco's protocol for exporting IP flow information. "
    .. "v5 is the classic fixed-format version; v9 is template-based and "
    .. "supports IPv6 and MPLS. Most enterprise routers support NetFlow export."))

o = s:option(Flag, "netflow_enabled", translate("Enable NetFlow Receiver"))
o.default = "0"

o = s:option(Value, "netflow_port", translate("NetFlow UDP Port"),
    translate("Port to listen on for incoming NetFlow datagrams."))
o.default = "2055"
o.datatype = "port"
o:depends("netflow_enabled", "1")

o = s:option(ListValue, "netflow_version", translate("NetFlow Version"),
    translate("Protocol version to accept. v9 is recommended for modern networks."))
o:value("5", "NetFlow v5 (fixed format)")
o:value("9", "NetFlow v9 (template-based)")
o:value("both", "Both v5 and v9")
o.default = "9"
o:depends("netflow_enabled", "1")

-- ---------------------------------------------------------------
-- Section: sFlow
-- ---------------------------------------------------------------
s = m:section(NamedSection, "collector", "flow_collection",
    translate("sFlow"),
    translate("sFlow samples a subset of packets at configurable rates and exports "
    .. "the samples plus interface counters. It is widely supported by switches "
    .. "from many vendors and scales well in high-throughput environments."))

o = s:option(Flag, "sflow_enabled", translate("Enable sFlow Receiver"))
o.default = "0"

o = s:option(Value, "sflow_port", translate("sFlow UDP Port"),
    translate("Port to listen on for incoming sFlow datagrams."))
o.default = "6343"
o.datatype = "port"
o:depends("sflow_enabled", "1")

-- ---------------------------------------------------------------
-- Section: IPFIX
-- ---------------------------------------------------------------
s = m:section(NamedSection, "collector", "flow_collection",
    translate("IPFIX"),
    translate("IPFIX (IP Flow Information Export) is the IETF standard successor "
    .. "to NetFlow v9. It uses a flexible template mechanism and supports "
    .. "enterprise-specific information elements for rich flow metadata."))

o = s:option(Flag, "ipfix_enabled", translate("Enable IPFIX Receiver"))
o.default = "0"

o = s:option(Value, "ipfix_port", translate("IPFIX UDP Port"),
    translate("Port to listen on for incoming IPFIX datagrams."))
o.default = "4739"
o.datatype = "port"
o:depends("ipfix_enabled", "1")

return m
