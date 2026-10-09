-- CBI model: Traffic Behavior Analysis

local m, s, o

m = Map("ndpi", translate("Traffic Behavior Analysis"),
    translate("Monitor periodic and recurring network flows to map active services "
    .. "and detect anomalies. Behavioral analysis learns what 'normal' looks like "
    .. "for your network and alerts when traffic patterns deviate significantly."))

-- ---------------------------------------------------------------
-- Section: Behavior Engine
-- ---------------------------------------------------------------
s = m:section(NamedSection, "behavior", "traffic_behavior",
    translate("Behavior Engine"))
s.addremove = false

o = s:option(Flag, "enabled", translate("Enable Behavior Analysis"),
    translate("Activate the traffic behavior monitoring engine. It runs in "
    .. "the background, periodically scanning active flows for patterns."))
o.default = "1"

o = s:option(Flag, "periodic_scan", translate("Periodic Flow Scanning"),
    translate("Scan flows at regular intervals to identify periodic, recurring "
    .. "connections such as NTP, heartbeats, polling, and cron-triggered traffic."))
o.default = "1"

o = s:option(Value, "scan_interval", translate("Scan Interval (seconds)"),
    translate("How often to run the periodic flow scanner. Lower values increase "
    .. "detection speed but use more CPU on resource-constrained devices."))
o.default = "60"
o.datatype = "uinteger"

o = s:option(Flag, "anomaly_detection", translate("Statistical Anomaly Detection"),
    translate("Compare current traffic patterns against a learned baseline. "
    .. "Alerts are raised when the deviation exceeds the configured threshold."))
o.default = "1"

o = s:option(Value, "baseline_hours", translate("Baseline Window (hours)"),
    translate("Number of hours of historical data to use as the normal baseline. "
    .. "A longer window produces a more stable model but adapts more slowly."))
o.default = "24"
o.datatype = "uinteger"

o = s:option(Value, "deviation_threshold", translate("Deviation Threshold (sigma)"),
    translate("Number of standard deviations from the baseline mean that "
    .. "triggers an anomaly alert. Typical values: 2 = sensitive, 3 = balanced, 5 = conservative."))
o.default = "3"
o.datatype = "ufloat"

-- ---------------------------------------------------------------
-- Section: Site Hierarchy (ntopng v7.0 inspired)
-- ---------------------------------------------------------------
s = m:section(NamedSection, "sites", "site_hierarchy",
    translate("Site Hierarchy"),
    translate("Group hosts and networks into logical sites for dashboard views. "
    .. "Inspired by ntopng 7.0's Sites feature, this allows you to see "
    .. "traffic patterns organized by physical location or network segment."))

o = s:option(Flag, "enabled", translate("Enable Site Hierarchy"))
o.default = "0"

o = s:option(Value, "site_name", translate("Site Name"),
    translate("A human-readable name for this network site."))
o.default = "Default"
o:depends("enabled", "1")

o = s:option(ListValue, "group_mode", translate("Grouping Mode"),
    translate("How to organize hosts into the site view."))
o:value("subnet", translate("By Subnet"))
o:value("vlan", translate("By VLAN"))
o:value("interface", translate("By Interface"))
o:value("manual", translate("Manual Assignment"))
o.default = "subnet"
o:depends("enabled", "1")

return m
