-- CBI model: Alerts & Security Settings

local m, s, o

m = Map("ndpi", translate("Alerts & Security"),
    translate("Configure security alerting, SIEM integration, and threat detection. "
    .. "nDPI can detect port scans, SYN floods, DNS tunneling, and other "
    .. "suspicious network behavior patterns."))

-- ---------------------------------------------------------------
-- Section: Alert Settings
-- ---------------------------------------------------------------
s = m:section(NamedSection, "alerts", "security",
    translate("Alert Configuration"))
s.addremove = false

o = s:option(Flag, "enabled", translate("Enable Alerting"),
    translate("Turn on the alert engine. When active, nDPI raises alerts "
    .. "for security events, threshold breaches, and anomalous traffic."))
o.default = "1"

o = s:option(Value, "max_alerts", translate("Max Stored Alerts"),
    translate("Maximum number of alerts to keep in memory. Oldest alerts "
    .. "are discarded when this limit is reached."))
o.default = "500"
o.datatype = "uinteger"

o = s:option(Value, "alert_log", translate("Alert Log File"),
    translate("Path to the file where alerts are written. The dashboard "
    .. "reads the last 50 entries from this file."))
o.default = "/tmp/ndpi_alerts.log"
o.datatype = "string"

o = s:option(Flag, "syslog_enabled", translate("Log to Syslog"),
    translate("Forward alerts to the system log (logread). Useful for "
    .. "centralized log collection and SIEM integration."))
o.default = "1"

-- ---------------------------------------------------------------
-- Section: Notification
-- ---------------------------------------------------------------
s = m:section(NamedSection, "alerts", "security",
    translate("Notification Settings"))

o = s:option(Flag, "email_enabled", translate("Email Notifications"),
    translate("Send email notifications for critical alerts. Requires "
    .. "a working SMTP configuration on the router (e.g., msmtp)."))
o.default = "0"

o = s:option(Value, "email_recipient", translate("Recipient Email"),
    translate("Email address to receive alert notifications."))
o.datatype = "string"
o:depends("email_enabled", "1")

-- ---------------------------------------------------------------
-- Section: Thresholds
-- ---------------------------------------------------------------
s = m:section(NamedSection, "alerts", "security",
    translate("Threshold Alerts"))

o = s:option(Value, "threshold_bandwidth", translate("Bandwidth Threshold (bytes/sec)"),
    translate("Alert when a single host exceeds this bandwidth. "
    .. "Set to 0 to disable this check."))
o.default = "0"
o.datatype = "uinteger"

o = s:option(Value, "threshold_connections", translate("Connection Count Threshold"),
    translate("Alert when a single host has more than this many concurrent "
    .. "connections. Can indicate a compromised device or P2P activity."))
o.default = "1000"
o.datatype = "uinteger"

-- ---------------------------------------------------------------
-- Section: Security Detection
-- ---------------------------------------------------------------
s = m:section(NamedSection, "alerts", "security",
    translate("Security Detection"),
    translate("nDPI can detect various network attacks and suspicious behaviors. "
    .. "These integrate with MITRE ATT&CK tactics for security analysts."))

o = s:option(Flag, "detect_port_scan", translate("Port Scan Detection"),
    translate("Detect hosts that probe many ports in quick succession. "
    .. "Maps to MITRE ATT&CK T1046 (Network Service Scanning)."))
o.default = "1"

o = s:option(Flag, "detect_syn_flood", translate("SYN Flood Detection"),
    translate("Detect TCP SYN flood denial-of-service patterns. "
    .. "Maps to MITRE ATT&CK T1498 (Network Denial of Service)."))
o.default = "1"

o = s:option(Flag, "detect_dns_tunnel", translate("DNS Tunneling Detection"),
    translate("Detect DNS queries with unusually long or encoded subdomains, "
    .. "which may indicate data exfiltration or C2 tunneling over DNS. "
    .. "Maps to MITRE ATT&CK T1071.004 (DNS-based Application Layer Protocol)."))
o.default = "1"

return m
