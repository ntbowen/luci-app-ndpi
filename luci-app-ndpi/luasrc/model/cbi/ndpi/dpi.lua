-- CBI model: DPI & Traffic Analysis Settings
-- Shows ALL individual nDPI 6.0 protocols organized by category

local m, s, o

m = Map("ndpi", translate("Traffic Analysis & Deep Packet Inspection"),
    translate("Configure nDPI's deep packet inspection engine and enable/disable "
    .. "individual protocol detection. nDPI 6.0 supports 480+ protocol signatures "
    .. "including TLS/QUIC fingerprinting, encrypted traffic classification, and "
    .. "industrial protocol detection."))

-- Include the nDPI CSS for multi-column protocol layout
local css_inc = m:section(SimpleSection)
css_inc.template = "cbi/nullsection"
local css_link = css_inc:option(DummyValue, "_css")
css_link.rawhtml = true
css_link.default = '<link rel="stylesheet" href="/luci-static/ndpi/css/ndpi.css" />'

-- ---------------------------------------------------------------
-- Section: DPI Engine Configuration
-- ---------------------------------------------------------------
s = m:section(NamedSection, "dpi", "analysis",
    translate("DPI Engine Settings"))
s.addremove = false

o = s:option(Flag, "tls_fingerprint", translate("TLS Fingerprinting (JA3/JA4)"),
    translate("Enable TLS client hello fingerprinting to identify applications "
    .. "by their TLS handshake patterns."))
o.default = "1"

o = s:option(Flag, "quic_detection", translate("QUIC Protocol Detection"),
    translate("Identify QUIC (HTTP/3) connections and extract SNI from "
    .. "the initial crypto frame."))
o.default = "1"

o = s:option(Flag, "dns_analysis", translate("DNS Traffic Analysis"),
    translate("Parse DNS queries and responses to map domain names to IP flows."))
o.default = "1"

o = s:option(Flag, "http_analysis", translate("HTTP/HTTPS Header Analysis"),
    translate("Inspect HTTP headers and HTTPS SNI to classify web traffic."))
o.default = "1"

o = s:option(Flag, "ssh_fingerprint", translate("SSH Fingerprinting (HASSH)"),
    translate("Generate HASSH fingerprints from SSH handshakes."))
o.default = "1"

o = s:option(Flag, "ja3_fingerprint", translate("JA3 Hash Generation"),
    translate("Compute JA3 fingerprint hashes for every TLS client hello."))
o.default = "1"

o = s:option(Flag, "ja4_fingerprint", translate("JA4+ Fingerprint Suite"),
    translate("Enable JA4+ family of fingerprints (JA4, JA4S, JA4H, JA4L, JA4X)."))
o.default = "1"

o = s:option(Flag, "hassh_fingerprint", translate("HASSH Fingerprinting"),
    translate("Produce HASSH fingerprints from SSH key exchange parameters."))
o.default = "1"

o = s:option(Flag, "detect_encrypted", translate("Encrypted Traffic Classification"),
    translate("Classify encrypted traffic using packet size and timing analysis."))
o.default = "1"

o = s:option(Flag, "stun_whatsapp", translate("STUN/VoIP Call Detection"),
    translate("Identify VoIP calls carried over STUN/TURN (WhatsApp, Teams, Zoom)."))
o.default = "1"

-- ---------------------------------------------------------------
-- Helper: add a protocol flag
-- ---------------------------------------------------------------
local function add_proto(section, key, label, desc)
    local opt = section:option(Flag, "proto_" .. key:lower(), translate(label))
    if desc then opt.description = translate(desc) end
    opt.default = "1"
    opt.rmempty = false
    return opt
end

-- ---------------------------------------------------------------
-- Protocol Categories heading
-- ---------------------------------------------------------------
local proto_hdr = m:section(SimpleSection)
proto_hdr.template = "cbi/nullsection"
local hdr = proto_hdr:option(DummyValue, "_proto_header")
hdr.rawhtml = true
hdr.default = '<h2 style="margin:24px 0 8px;border-bottom:2px solid #2563eb;padding-bottom:6px">'
    .. translate("Protocol Categories") .. '</h2>'
    .. '<p style="color:#6b7280;margin:0 0 12px">'
    .. translate("Enable or disable detection of individual protocols. "
    .. "Protocols are grouped by category.") .. '</p>'

-- ---------------------------------------------------------------
-- Section: Web & HTTP Protocols
-- ---------------------------------------------------------------
s = m:section(NamedSection, "protocols", "ndpi_protocols",
    translate("Web & HTTP Protocols"),
    translate("HTTP, HTTPS, web browsers and web-based services."))
s.addremove = false

add_proto(s, "HTTP", "HTTP")
add_proto(s, "HTTP2", "HTTP/2")
add_proto(s, "HTTP_CONNECT", "HTTP CONNECT")
add_proto(s, "HTTP_PROXY", "HTTP Proxy")
add_proto(s, "TLS", "TLS/SSL")
add_proto(s, "DTLS", "DTLS")
add_proto(s, "QUIC", "QUIC (HTTP/3)")
add_proto(s, "HLS", "HLS (HTTP Live Streaming)")
add_proto(s, "MPEGDASH", "MPEG-DASH")
add_proto(s, "MPEGTS", "MPEG-TS")
add_proto(s, "WEBSOCKET", "WebSocket")
add_proto(s, "WEBDAV", "WebDAV")
add_proto(s, "FASTCGI", "FastCGI")
add_proto(s, "SOAP", "SOAP")
add_proto(s, "JSON_RPC", "JSON-RPC")
add_proto(s, "PROTOBUF", "Protocol Buffers")
add_proto(s, "MSGPACK", "MessagePack")
add_proto(s, "SOCKS", "SOCKS Proxy")
add_proto(s, "OCSP", "OCSP")

-- ---------------------------------------------------------------
-- Section: DNS Protocols
-- ---------------------------------------------------------------
s = m:section(NamedSection, "protocols", "ndpi_protocols",
    translate("DNS Protocols"),
    translate("Domain Name System protocols including encrypted variants."))
s.addremove = false

add_proto(s, "DNS", "DNS")
add_proto(s, "DOH_DOT", "DNS-over-HTTPS / DNS-over-TLS")
add_proto(s, "DNSCRYPT", "DNSCrypt")
add_proto(s, "MDNS", "mDNS (Multicast DNS)")
add_proto(s, "LLMNR", "LLMNR")
add_proto(s, "OPENDNS", "OpenDNS")
add_proto(s, "AVAST_SECUREDNS", "Avast SecureDNS")

-- ---------------------------------------------------------------
-- Section: Email Protocols
-- ---------------------------------------------------------------
s = m:section(NamedSection, "protocols", "ndpi_protocols",
    translate("Email Protocols"),
    translate("Email sending and receiving protocols."))
s.addremove = false

add_proto(s, "MAIL_SMTP", "SMTP")
add_proto(s, "MAIL_SMTPS", "SMTPS (SMTP over TLS)")
add_proto(s, "MAIL_IMAP", "IMAP")
add_proto(s, "MAIL_IMAPS", "IMAPS (IMAP over TLS)")
add_proto(s, "MAIL_POP", "POP3")
add_proto(s, "MAIL_POPS", "POP3S (POP3 over TLS)")

-- ---------------------------------------------------------------
-- Section: VoIP & Video Conferencing
-- ---------------------------------------------------------------
s = m:section(NamedSection, "protocols", "ndpi_protocols",
    translate("VoIP & Video Conferencing"),
    translate("Voice-over-IP, video calls and conferencing protocols."))
s.addremove = false

add_proto(s, "SIP", "SIP")
add_proto(s, "SKINNY", "Skinny (SCCP)")
add_proto(s, "H323", "H.323")
add_proto(s, "IAX", "IAX (Asterisk)")
add_proto(s, "MGCP", "MGCP")
add_proto(s, "MEGACO", "Megaco/H.248")
add_proto(s, "RTP", "RTP")
add_proto(s, "RTCP", "RTCP")
add_proto(s, "SRTP", "SRTP")
add_proto(s, "STUN", "STUN")
add_proto(s, "NOE", "NOE (Alcatel)")
add_proto(s, "BFCP", "BFCP")
add_proto(s, "ZOOM", "Zoom")
add_proto(s, "MSTEAMS", "Microsoft Teams")
add_proto(s, "MSTEAMS_CALL", "Microsoft Teams Call")
add_proto(s, "GOOGLE_MEET", "Google Meet")
add_proto(s, "GOOGLE_CALL", "Google Call")
add_proto(s, "WEBEX", "Webex")
add_proto(s, "GOTO", "GoTo Meeting")
add_proto(s, "FUZE", "Fuze")
add_proto(s, "PALTALK", "Paltalk")
add_proto(s, "MUMBLE", "Mumble")
add_proto(s, "TEAMSPEAK", "TeamSpeak")
add_proto(s, "VIVOX", "Vivox")
add_proto(s, "DISCORD_CALL", "Discord Call")

-- ---------------------------------------------------------------
-- Section: Messaging & Chat
-- ---------------------------------------------------------------
s = m:section(NamedSection, "protocols", "ndpi_protocols",
    translate("Messaging & Chat"),
    translate("Instant messaging and chat applications."))
s.addremove = false

add_proto(s, "WHATSAPP", "WhatsApp")
add_proto(s, "WHATSAPP_CALL", "WhatsApp Call")
add_proto(s, "WHATSAPP_FILES", "WhatsApp Files")
add_proto(s, "TELEGRAM", "Telegram")
add_proto(s, "TELEGRAM_VOIP", "Telegram VoIP")
add_proto(s, "SIGNAL", "Signal")
add_proto(s, "SIGNAL_VOIP", "Signal VoIP")
add_proto(s, "THREEMA", "Threema")
add_proto(s, "LINE", "LINE")
add_proto(s, "LINE_CALL", "LINE Call")
add_proto(s, "VIBER", "Viber")
add_proto(s, "VIBER_VOIP", "Viber VoIP")
add_proto(s, "WECHAT", "WeChat")
add_proto(s, "KAKAOTALK", "KakaoTalk")
add_proto(s, "KAKAOTALK_VOICE", "KakaoTalk Voice")
add_proto(s, "SLACK", "Slack")
add_proto(s, "DISCORD", "Discord")
add_proto(s, "JABBER", "Jabber/XMPP")
add_proto(s, "IRC", "IRC")
add_proto(s, "IMO", "imo")
add_proto(s, "DINGTALK", "DingTalk")
add_proto(s, "GOOGLE_CHAT", "Google Chat")
add_proto(s, "FACEBOOK_MESSENGER", "Facebook Messenger")

-- ---------------------------------------------------------------
-- Section: Social Media
-- ---------------------------------------------------------------
s = m:section(NamedSection, "protocols", "ndpi_protocols",
    translate("Social Media"),
    translate("Social networking platforms."))
s.addremove = false

add_proto(s, "FACEBOOK", "Facebook")
add_proto(s, "FACEBOOK_REEL_STORY", "Facebook Reel/Story")
add_proto(s, "FACEBOOK_VOIP", "Facebook VoIP")
add_proto(s, "INSTAGRAM", "Instagram")
add_proto(s, "TWITTER", "Twitter/X")
add_proto(s, "THREADS", "Threads")
add_proto(s, "TIKTOK", "TikTok")
add_proto(s, "SNAPCHAT", "Snapchat")
add_proto(s, "SNAPCHAT_CALL", "Snapchat Call")
add_proto(s, "REDDIT", "Reddit")
add_proto(s, "PINTEREST", "Pinterest")
add_proto(s, "LINKEDIN", "LinkedIn")
add_proto(s, "TUMBLR", "Tumblr")
add_proto(s, "VK", "VK")
add_proto(s, "BADOO", "Badoo")
add_proto(s, "LIKEE", "Likee")
add_proto(s, "MASTODON", "Mastodon")
add_proto(s, "BLUESKY", "Bluesky")
add_proto(s, "SINA_WEIBO", "Sina Weibo")
add_proto(s, "QQ", "QQ")
add_proto(s, "OICQ", "OICQ")

-- ---------------------------------------------------------------
-- Section: Streaming & Media
-- ---------------------------------------------------------------
s = m:section(NamedSection, "protocols", "ndpi_protocols",
    translate("Streaming & Media"),
    translate("Audio and video streaming services."))
s.addremove = false

add_proto(s, "NETFLIX", "Netflix")
add_proto(s, "YOUTUBE", "YouTube")
add_proto(s, "YOUTUBE_KIDS", "YouTube Kids")
add_proto(s, "YOUTUBE_UPLOAD", "YouTube Upload")
add_proto(s, "AMAZON_VIDEO", "Amazon Prime Video")
add_proto(s, "DISNEYPLUS", "Disney+")
add_proto(s, "HBO", "HBO Max")
add_proto(s, "HULU", "Hulu")
add_proto(s, "PARAMOUNTPLUS", "Paramount+")
add_proto(s, "APPLETVPLUS", "Apple TV+")
add_proto(s, "DAZN", "DAZN")
add_proto(s, "ESPN", "ESPN")
add_proto(s, "DIRECTV", "DirecTV")
add_proto(s, "SHOWTIME", "Showtime")
add_proto(s, "VUDU", "Vudu")
add_proto(s, "TWITCH", "Twitch")
add_proto(s, "KICK", "Kick")
add_proto(s, "DAILYMOTION", "Dailymotion")
add_proto(s, "VIMEO", "Vimeo")
add_proto(s, "RUMBLE", "Rumble")
add_proto(s, "RUTUBE", "Rutube")
add_proto(s, "LIVESTREAM", "Livestream")
add_proto(s, "IQIYI", "iQIYI")
add_proto(s, "IFLIX", "iflix")
add_proto(s, "TENCENTVIDEO", "Tencent Video")
add_proto(s, "SPOTIFY", "Spotify")
add_proto(s, "DEEZER", "Deezer")
add_proto(s, "SOUNDCLOUD", "SoundCloud")
add_proto(s, "TIDAL", "Tidal")
add_proto(s, "PANDORA", "Pandora")
add_proto(s, "IHEARTRADIO", "iHeartRadio")
add_proto(s, "LASTFM", "Last.fm")
add_proto(s, "TUNEIN", "TuneIn")
add_proto(s, "ICECAST", "Icecast")
add_proto(s, "RTMP", "RTMP")
add_proto(s, "RTSP", "RTSP")
add_proto(s, "SONOS", "Sonos")

-- ---------------------------------------------------------------
-- Section: Cloud Services & Providers
-- ---------------------------------------------------------------
s = m:section(NamedSection, "protocols", "ndpi_protocols",
    translate("Cloud Services & Providers"),
    translate("Major cloud platforms and CDN services."))
s.addremove = false

add_proto(s, "AMAZON_AWS", "Amazon AWS")
add_proto(s, "AWS_S3", "AWS S3")
add_proto(s, "AWS_EC2", "AWS EC2")
add_proto(s, "AWS_CLOUDFRONT", "AWS CloudFront")
add_proto(s, "AWS_API_GATEWAY", "AWS API Gateway")
add_proto(s, "AWS_COGNITO", "AWS Cognito")
add_proto(s, "AWS_DYNAMODB", "AWS DynamoDB")
add_proto(s, "AWS_EMR", "AWS EMR")
add_proto(s, "AWS_KINESIS", "AWS Kinesis")
add_proto(s, "MICROSOFT_AZURE", "Microsoft Azure")
add_proto(s, "GOOGLE_CLOUD", "Google Cloud")
add_proto(s, "CLOUDFLARE", "Cloudflare")
add_proto(s, "CLOUDFLARE_WARP", "Cloudflare WARP")
add_proto(s, "AKAMAI", "Akamai")
add_proto(s, "EDGECAST", "Edgecast")
add_proto(s, "CACHEFLY", "CacheFly")
add_proto(s, "DIGITALOCEAN", "DigitalOcean")
add_proto(s, "ALICLOUD", "Alibaba Cloud")
add_proto(s, "HUAWEI_CLOUD", "Huawei Cloud")
add_proto(s, "YANDEX_CLOUD", "Yandex Cloud")
add_proto(s, "SALESFORCE", "Salesforce")
add_proto(s, "DROPBOX", "Dropbox")
add_proto(s, "MS_ONE_DRIVE", "Microsoft OneDrive")
add_proto(s, "GOOGLE_DRIVE", "Google Drive")
add_proto(s, "APPLE_ICLOUD", "Apple iCloud")
add_proto(s, "ICLOUD_PRIVATE_RELAY", "iCloud Private Relay")
add_proto(s, "GOOGLE_DOCS", "Google Docs")

-- ---------------------------------------------------------------
-- Section: Big Tech & Platforms
-- ---------------------------------------------------------------
s = m:section(NamedSection, "protocols", "ndpi_protocols",
    translate("Big Tech & Platform Traffic"),
    translate("Traffic from major technology companies and platforms."))
s.addremove = false

add_proto(s, "GOOGLE", "Google")
add_proto(s, "GOOGLE_SERVICES", "Google Services")
add_proto(s, "GOOGLE_MAPS", "Google Maps")
add_proto(s, "GOOGLE_CLASSROOM", "Google Classroom")
add_proto(s, "GMAIL", "Gmail")
add_proto(s, "PLAYSTORE", "Google Play Store")
add_proto(s, "APPLE", "Apple")
add_proto(s, "APPLE_PUSH", "Apple Push Notification")
add_proto(s, "APPLE_SIRI", "Apple Siri")
add_proto(s, "APPLE_ITUNES", "Apple iTunes")
add_proto(s, "APPLESTORE", "Apple App Store")
add_proto(s, "MICROSOFT", "Microsoft")
add_proto(s, "MICROSOFT_365", "Microsoft 365")
add_proto(s, "MS_OUTLOOK", "Microsoft Outlook")
add_proto(s, "WINDOWS_UPDATE", "Windows Update")
add_proto(s, "MSDO", "Microsoft Delivery Optimization")
add_proto(s, "AMAZON", "Amazon")
add_proto(s, "AMAZON_ALEXA", "Amazon Alexa")
add_proto(s, "ALIBABA", "Alibaba")
add_proto(s, "TAOBAO", "Taobao")
add_proto(s, "TEMU", "Temu")
add_proto(s, "SHEIN", "Shein")
add_proto(s, "EBAY", "eBay")
add_proto(s, "YAHOO", "Yahoo")
add_proto(s, "MOZILLA", "Mozilla")
add_proto(s, "WIKIPEDIA", "Wikipedia")
add_proto(s, "BLOOMBERG", "Bloomberg")
add_proto(s, "PLURALSIGHT", "Pluralsight")
add_proto(s, "PASTEBIN", "Pastebin")
add_proto(s, "HUAWEI", "Huawei")
add_proto(s, "XIAOMI", "Xiaomi")
add_proto(s, "SAMSUNG_SDP", "Samsung SDP")
add_proto(s, "TENCENT", "Tencent")
add_proto(s, "NAVER", "Naver")
add_proto(s, "SINA", "Sina")
add_proto(s, "WAZE", "Waze")
add_proto(s, "CANONICAL", "Canonical/Ubuntu")

-- ---------------------------------------------------------------
-- Section: Developer & Code Platforms
-- ---------------------------------------------------------------
s = m:section(NamedSection, "protocols", "ndpi_protocols",
    translate("Developer & Code Platforms"),
    translate("Source code hosting, CI/CD and developer tools."))
s.addremove = false

add_proto(s, "GITHUB", "GitHub")
add_proto(s, "GITHUB_ACTIONS", "GitHub Actions")
add_proto(s, "GITHUB_COPILOT", "GitHub Copilot")
add_proto(s, "GITHUB_PACKAGES", "GitHub Packages")
add_proto(s, "GITLAB", "GitLab")
add_proto(s, "GIT", "Git")

-- ---------------------------------------------------------------
-- Section: VPN & Tunneling
-- ---------------------------------------------------------------
s = m:section(NamedSection, "protocols", "ndpi_protocols",
    translate("VPN & Tunneling"),
    translate("VPN services and tunnel protocols."))
s.addremove = false

add_proto(s, "OPENVPN", "OpenVPN")
add_proto(s, "WIREGUARD", "WireGuard")
add_proto(s, "IPSEC", "IPsec")
add_proto(s, "PPTP", "PPTP")
add_proto(s, "CISCOVPN", "Cisco VPN (AnyConnect)")
add_proto(s, "FORTICLIENT", "FortiClient VPN")
add_proto(s, "SOFTETHER", "SoftEther")
add_proto(s, "TAILSCALE", "Tailscale")
add_proto(s, "NORDVPN", "NordVPN")
add_proto(s, "PROTONVPN", "ProtonVPN")
add_proto(s, "SURFSHARK", "Surfshark")
add_proto(s, "MULLVAD", "Mullvad VPN")
add_proto(s, "PIA", "Private Internet Access")
add_proto(s, "OPERA_VPN", "Opera VPN")
add_proto(s, "HOTSPOT_SHIELD", "Hotspot Shield")
add_proto(s, "TUNNELBEAR", "TunnelBear")
add_proto(s, "WINDSCRIBE", "Windscribe")
add_proto(s, "CACTUSVPN", "CactusVPN")
add_proto(s, "ULTRASURF", "Ultrasurf")
add_proto(s, "PSIPHON", "Psiphon")
add_proto(s, "HAMACHI", "Hamachi")
add_proto(s, "TINC", "tinc")
add_proto(s, "NEBULA", "Nebula")
add_proto(s, "YGGDRASIL", "Yggdrasil")
add_proto(s, "TOR", "Tor")
add_proto(s, "VXLAN", "VXLAN")
add_proto(s, "TEREDO", "Teredo")
add_proto(s, "IP_GRE", "GRE")
add_proto(s, "IP_IP_IN_IP", "IP-in-IP")
add_proto(s, "IP_ESP", "ESP")
add_proto(s, "IP_AH", "AH")

-- ---------------------------------------------------------------
-- Section: Remote Access
-- ---------------------------------------------------------------
s = m:section(NamedSection, "protocols", "ndpi_protocols",
    translate("Remote Access & Desktop"),
    translate("Remote desktop and screen-sharing protocols."))
s.addremove = false

add_proto(s, "SSH", "SSH")
add_proto(s, "TELNET", "Telnet")
add_proto(s, "RDP", "RDP (Remote Desktop)")
add_proto(s, "VNC", "VNC")
add_proto(s, "TEAMVIEWER", "TeamViewer")
add_proto(s, "ANYDESK", "AnyDesk")
add_proto(s, "NOMACHINE", "NoMachine")
add_proto(s, "RADMIN", "Radmin")
add_proto(s, "CITRIX", "Citrix")
add_proto(s, "XDMCP", "XDMCP")
add_proto(s, "RSH", "RSH")

-- ---------------------------------------------------------------
-- Section: File Transfer
-- ---------------------------------------------------------------
s = m:section(NamedSection, "protocols", "ndpi_protocols",
    translate("File Transfer"),
    translate("File transfer and synchronization protocols."))
s.addremove = false

add_proto(s, "FTP_CONTROL", "FTP Control")
add_proto(s, "FTP_DATA", "FTP Data")
add_proto(s, "FTPS", "FTPS (FTP over TLS)")
add_proto(s, "TFTP", "TFTP")
add_proto(s, "NFS", "NFS")
add_proto(s, "SMBV1", "SMBv1")
add_proto(s, "SMBV23", "SMBv2/v3")
add_proto(s, "AFP", "AFP (Apple Filing)")
add_proto(s, "RSYNC", "rsync")
add_proto(s, "SYNCTHING", "Syncthing")
add_proto(s, "UFTP", "UFTP")

-- ---------------------------------------------------------------
-- Section: Peer-to-Peer
-- ---------------------------------------------------------------
s = m:section(NamedSection, "protocols", "ndpi_protocols",
    translate("Peer-to-Peer"),
    translate("P2P file sharing and distributed protocols."))
s.addremove = false

add_proto(s, "BITTORRENT", "BitTorrent")
add_proto(s, "EDONKEY", "eDonkey")
add_proto(s, "GNUTELLA", "Gnutella")
add_proto(s, "USENET", "Usenet (NNTP)")
add_proto(s, "LIBP2P", "libp2p")

-- ---------------------------------------------------------------
-- Section: Gaming
-- ---------------------------------------------------------------
s = m:section(NamedSection, "protocols", "ndpi_protocols",
    translate("Gaming"),
    translate("Online gaming platforms and game protocols."))
s.addremove = false

add_proto(s, "STEAM", "Steam")
add_proto(s, "EPICGAMES", "Epic Games")
add_proto(s, "XBOX", "Xbox")
add_proto(s, "PLAYSTATION", "PlayStation")
add_proto(s, "NINTENDO", "Nintendo")
add_proto(s, "ROBLOX", "Roblox")
add_proto(s, "RIOTGAMES", "Riot Games (LoL, Valorant)")
add_proto(s, "BLIZZARD", "Blizzard (Battle.net)")
add_proto(s, "ELECTRONICARTS", "Electronic Arts")
add_proto(s, "ACTIVISION", "Activision")
add_proto(s, "ROCKSTAR_GAMES", "Rockstar Games")
add_proto(s, "DOTA2", "Dota 2")
add_proto(s, "WORLDOFWARCRAFT", "World of Warcraft")
add_proto(s, "GUILDWARS2", "Guild Wars 2")
add_proto(s, "TESO", "The Elder Scrolls Online")
add_proto(s, "HOTS", "Heroes of the Storm")
add_proto(s, "PATHOFEXILE", "Path of Exile")
add_proto(s, "AMONG_US", "Among Us")
add_proto(s, "FREEFIRE", "Free Fire")
add_proto(s, "COD_MOBILE", "Call of Duty Mobile")
add_proto(s, "GENSHIN_IMPACT", "Genshin Impact")
add_proto(s, "LOLWILDRIFT", "LoL Wild Rift")
add_proto(s, "TOCA_BOCA", "Toca Boca")
add_proto(s, "CROSSFIRE", "Crossfire")
add_proto(s, "DOFUS", "Dofus")
add_proto(s, "ARMAGETRON", "Armagetron")
add_proto(s, "SOURCE_ENGINE", "Source Engine")
add_proto(s, "VALVE_SDR", "Valve SDR")
add_proto(s, "RAKNET", "RakNet")
add_proto(s, "GAIJIN", "Gaijin (War Thunder)")
add_proto(s, "NEXON", "Nexon")
add_proto(s, "NETEASE_GAMES", "NetEase Games")
add_proto(s, "TENCENTGAMES", "Tencent Games")
add_proto(s, "I3D", "i3D.net")

-- ---------------------------------------------------------------
-- Section: Cloud Gaming
-- ---------------------------------------------------------------
s = m:section(NamedSection, "protocols", "ndpi_protocols",
    translate("Cloud Gaming & Streaming"),
    translate("Cloud gaming and game streaming services."))
s.addremove = false

add_proto(s, "GEFORCENOW", "GeForce Now")
add_proto(s, "BLACKNUT", "Blacknut")
add_proto(s, "BOOSTEROID", "Boosteroid")

-- ---------------------------------------------------------------
-- Section: Cryptocurrency & Mining
-- ---------------------------------------------------------------
s = m:section(NamedSection, "protocols", "ndpi_protocols",
    translate("Cryptocurrency & Mining"),
    translate("Cryptocurrency protocols and mining traffic."))
s.addremove = false

add_proto(s, "BITCOIN", "Bitcoin")
add_proto(s, "ETHEREUM", "Ethereum")
add_proto(s, "MONERO", "Monero")
add_proto(s, "MINING", "Mining (Generic)")
add_proto(s, "NANO", "Nano")

-- ---------------------------------------------------------------
-- Section: Network Infrastructure
-- ---------------------------------------------------------------
s = m:section(NamedSection, "protocols", "ndpi_protocols",
    translate("Network Infrastructure"),
    translate("Core network and infrastructure protocols."))
s.addremove = false

add_proto(s, "NTP", "NTP")
add_proto(s, "SNMP", "SNMP")
add_proto(s, "SYSLOG", "Syslog")
add_proto(s, "DHCP", "DHCP")
add_proto(s, "DHCPV6", "DHCPv6")
add_proto(s, "LDAP", "LDAP")
add_proto(s, "KERBEROS", "Kerberos")
add_proto(s, "RADIUS", "RADIUS")
add_proto(s, "NETBIOS", "NetBIOS")
add_proto(s, "SSDP", "SSDP")
add_proto(s, "WSD", "WSD")
add_proto(s, "NETFLOW", "NetFlow")
add_proto(s, "SFLOW", "sFlow")
add_proto(s, "BGP", "BGP")
add_proto(s, "OSPF", "OSPF")
add_proto(s, "IP_OSPF", "IP OSPF")
add_proto(s, "LDP", "LDP")
add_proto(s, "LISP", "LISP")
add_proto(s, "OPENFLOW", "OpenFlow")
add_proto(s, "CAPWAP", "CAPWAP")
add_proto(s, "IP_ICMP", "ICMP")
add_proto(s, "IP_ICMPV6", "ICMPv6")
add_proto(s, "IP_IGMP", "IGMP")
add_proto(s, "IP_SCTP", "SCTP")
add_proto(s, "IP_PGM", "PGM")
add_proto(s, "IP_PIM", "PIM")
add_proto(s, "IP_EGP", "EGP")
add_proto(s, "IP_VRRP", "VRRP")
add_proto(s, "HSRP", "HSRP")
add_proto(s, "GLBP", "GLBP")
add_proto(s, "BFD", "BFD")
add_proto(s, "CPHA", "CPHA (Check Point HA)")
add_proto(s, "DLEP", "DLEP")
add_proto(s, "NATPMP", "NAT-PMP")
add_proto(s, "WHOIS_DAS", "WHOIS/DAS")
add_proto(s, "Z3950", "Z39.50")
add_proto(s, "IPP", "IPP (Printing)")
add_proto(s, "BJNP", "BJNP (Canon Printing)")
add_proto(s, "GTP", "GTP")
add_proto(s, "GTP_C", "GTP-C")
add_proto(s, "GTP_U", "GTP-U")
add_proto(s, "GTP_PRIME", "GTP Prime")
add_proto(s, "PFCP", "PFCP")
add_proto(s, "DIAMETER", "Diameter")
add_proto(s, "SERVICE_LOCATION", "SLP (Service Location)")
add_proto(s, "DCERPC", "DCE/RPC")
add_proto(s, "MS_RPCH", "MS RPC over HTTP")
add_proto(s, "SMPP", "SMPP")

-- ---------------------------------------------------------------
-- Section: Database Protocols
-- ---------------------------------------------------------------
s = m:section(NamedSection, "protocols", "ndpi_protocols",
    translate("Database Protocols"),
    translate("Database and data store access protocols."))
s.addremove = false

add_proto(s, "MYSQL", "MySQL")
add_proto(s, "POSTGRES", "PostgreSQL")
add_proto(s, "MSSQL_TDS", "MS SQL Server (TDS)")
add_proto(s, "ORACLE", "Oracle DB")
add_proto(s, "MONGODB", "MongoDB")
add_proto(s, "CASSANDRA", "Cassandra")
add_proto(s, "ELASTICSEARCH", "Elasticsearch")
add_proto(s, "CLICKHOUSE", "ClickHouse")
add_proto(s, "DRDA", "DRDA (DB2)")
add_proto(s, "REDIS", "Redis") -- using RESP
add_proto(s, "RESP", "RESP (Redis Protocol)")
add_proto(s, "MEMCACHED", "Memcached")
add_proto(s, "CEPH", "Ceph")
add_proto(s, "LUSTRE", "Lustre")

-- ---------------------------------------------------------------
-- Section: Message Queues & Middleware
-- ---------------------------------------------------------------
s = m:section(NamedSection, "protocols", "ndpi_protocols",
    translate("Message Queues & Middleware"),
    translate("Message brokers, queues and middleware protocols."))
s.addremove = false

add_proto(s, "MQTT", "MQTT")
add_proto(s, "AMQP", "AMQP")
add_proto(s, "APACHE_KAFKA", "Apache Kafka")
add_proto(s, "APACHE_THRIFT", "Apache Thrift")
add_proto(s, "ZMQ", "ZeroMQ")
add_proto(s, "NATS", "NATS")
add_proto(s, "STOMP", "STOMP")
add_proto(s, "OPENWIRE", "OpenWire (ActiveMQ)")
add_proto(s, "GEARMAN", "Gearman")
add_proto(s, "COLLECTD", "collectd")
add_proto(s, "MUNIN", "Munin")
add_proto(s, "ZABBIX", "Zabbix")
add_proto(s, "CHECKMK", "Checkmk")

-- ---------------------------------------------------------------
-- Section: Industrial Control Systems (ICS/SCADA)
-- ---------------------------------------------------------------
s = m:section(NamedSection, "protocols", "ndpi_protocols",
    translate("Industrial Control Systems (ICS/SCADA)"),
    translate("Industrial automation, SCADA, and OT protocols. "
    .. "Critical for securing operational technology networks."))
s.addremove = false

add_proto(s, "MODBUS", "Modbus")
add_proto(s, "S7COMM", "S7comm (Siemens S7)")
add_proto(s, "S7COMM_PLUS", "S7comm Plus")
add_proto(s, "PROFINET_IO", "PROFINET IO")
add_proto(s, "OPC_UA", "OPC-UA")
add_proto(s, "IEC60870", "IEC 60870-5-104")
add_proto(s, "IEC62056", "IEC 62056 (DLMS/COSEM)")
add_proto(s, "IEEE_C37118", "IEEE C37.118 (Synchrophasor)")
add_proto(s, "BACNET", "BACnet")
add_proto(s, "KNXNET_IP", "KNXnet/IP")
add_proto(s, "DNP3", "DNP3")
add_proto(s, "ETHERNET_IP", "EtherNet/IP")
add_proto(s, "CIP", "CIP (Common Industrial)")
add_proto(s, "SOMEIP", "SOME/IP")
add_proto(s, "ISO9506_1_MMS", "MMS (ISO 9506)")
add_proto(s, "TRISTATION", "TriStation")
add_proto(s, "UMAS", "UMAS")
add_proto(s, "FINS", "FINS (Omron)")
add_proto(s, "MELSEC", "MELSEC (Mitsubishi)")
add_proto(s, "BECKHOFF_ADS", "Beckhoff ADS/AMS")
add_proto(s, "HART_IP", "HART-IP")
add_proto(s, "CNP_IP", "CNP/IP")
add_proto(s, "C1222", "C12.22 (ANSI)")
add_proto(s, "TRDP", "TRDP (Train Protocol)")
add_proto(s, "ETHERSBUS", "EtherSBus")
add_proto(s, "ETHERSIO", "EtherSIO")
add_proto(s, "CAN", "CAN bus")
add_proto(s, "TARGUS_GETDATA", "Targus Getdata")
add_proto(s, "ATG", "ATG (Tank Gauging)")
add_proto(s, "PTPV2", "PTPv2 (IEEE 1588)")
add_proto(s, "HISLIP", "HiSLIP (LXI)")

-- ---------------------------------------------------------------
-- Section: IoT & Smart Home
-- ---------------------------------------------------------------
s = m:section(NamedSection, "protocols", "ndpi_protocols",
    translate("IoT & Smart Home"),
    translate("Internet of Things and smart home protocols."))
s.addremove = false

add_proto(s, "COAP", "CoAP")
add_proto(s, "MATTER", "Matter (Smart Home)")
add_proto(s, "TIVOCONNECT", "TiVo Connect")
add_proto(s, "TPLINK_SHP", "TP-Link Smart Home")
add_proto(s, "TUYA_LP", "Tuya (Smart Home)")
add_proto(s, "MESHTASTIC", "Meshtastic")
add_proto(s, "TESLA_SERVICES", "Tesla Services")
add_proto(s, "NEST_LOG_SINK", "Google Nest Log")
add_proto(s, "SONOS", "Sonos")

-- ---------------------------------------------------------------
-- Section: Medical
-- ---------------------------------------------------------------
s = m:section(NamedSection, "protocols", "ndpi_protocols",
    translate("Medical Protocols"),
    translate("Healthcare and medical imaging protocols."))
s.addremove = false

add_proto(s, "DICOM", "DICOM")
add_proto(s, "HL7", "HL7")

-- ---------------------------------------------------------------
-- Section: Network Equipment Vendors
-- ---------------------------------------------------------------
s = m:section(NamedSection, "protocols", "ndpi_protocols",
    translate("Network Equipment Vendors"),
    translate("Vendor-specific management and monitoring traffic."))
s.addremove = false

add_proto(s, "UBIQUITY", "Ubiquiti")
add_proto(s, "UBNTAC2", "UBNT AirControl 2")
add_proto(s, "MIKROTIK", "MikroTik")
add_proto(s, "MERAKI_CLOUD", "Meraki Cloud")
add_proto(s, "NTOP", "ntop")
add_proto(s, "VMWARE", "VMware")
add_proto(s, "HAPROXY", "HAProxy (PROXY protocol)")
add_proto(s, "KISMET", "Kismet")
add_proto(s, "RIPE_ATLAS", "RIPE Atlas")

-- ---------------------------------------------------------------
-- Section: Security & Antivirus
-- ---------------------------------------------------------------
s = m:section(NamedSection, "protocols", "ndpi_protocols",
    translate("Security & Antivirus"),
    translate("Security tools and antivirus traffic."))
s.addremove = false

add_proto(s, "AVAST", "Avast")
add_proto(s, "CYBERSECURITY", "Cybersecurity (Generic)")
add_proto(s, "CRASHLYSTICS", "Crashlytics")
add_proto(s, "DATASAVER", "Data Saver")
add_proto(s, "ROUGHTIME", "Roughtime")
add_proto(s, "IRIS", "IRIS")

-- ---------------------------------------------------------------
-- Section: Proton Suite
-- ---------------------------------------------------------------
s = m:section(NamedSection, "protocols", "ndpi_protocols",
    translate("Proton Suite"),
    translate("Proton privacy-focused services."))
s.addremove = false

add_proto(s, "PROTON", "Proton (Generic)")
add_proto(s, "PROTON_MAIL", "Proton Mail")
add_proto(s, "PROTON_DRIVE", "Proton Drive")
add_proto(s, "PROTON_CALENDAR", "Proton Calendar")
add_proto(s, "PROTON_PASS", "Proton Pass")
add_proto(s, "PROTON_DOCS", "Proton Docs")
add_proto(s, "PROTON_MEET", "Proton Meet")
add_proto(s, "PROTON_WALLET", "Proton Wallet")
add_proto(s, "PROTON_LUMO", "Proton Lumo")

-- ---------------------------------------------------------------
-- Section: Yandex Services
-- ---------------------------------------------------------------
s = m:section(NamedSection, "protocols", "ndpi_protocols",
    translate("Yandex Services"),
    translate("Yandex platform services."))
s.addremove = false

add_proto(s, "YANDEX", "Yandex (Generic)")
add_proto(s, "YANDEX_ALICE", "Yandex Alice")
add_proto(s, "YANDEX_DIRECT", "Yandex Direct")
add_proto(s, "YANDEX_DISK", "Yandex Disk")
add_proto(s, "YANDEX_MAIL", "Yandex Mail")
add_proto(s, "YANDEX_MARKET", "Yandex Market")
add_proto(s, "YANDEX_METRIKA", "Yandex Metrika")
add_proto(s, "YANDEX_MUSIC", "Yandex Music")

-- ---------------------------------------------------------------
-- Section: Speed Test & Network Tools
-- ---------------------------------------------------------------
s = m:section(NamedSection, "protocols", "ndpi_protocols",
    translate("Speed Test & Network Tools"),
    translate("Network speed testing and diagnostic tools."))
s.addremove = false

add_proto(s, "OOKLA", "Ookla Speedtest")
add_proto(s, "ACCUWEATHER", "AccuWeather")
add_proto(s, "EASYWEATHER", "EasyWeather")
add_proto(s, "EAQ", "EAQ")

-- ---------------------------------------------------------------
-- Section: Game Boosters & Accelerators
-- ---------------------------------------------------------------
s = m:section(NamedSection, "protocols", "ndpi_protocols",
    translate("Game Boosters & Accelerators"),
    translate("Game acceleration and network optimization services."))
s.addremove = false

add_proto(s, "GEARUP_BOOSTER", "GearUP Booster")
add_proto(s, "LAGOFAST", "LagoFast")
add_proto(s, "MUDFISH", "Mudfish")

-- ---------------------------------------------------------------
-- Section: Miscellaneous & Low-Level
-- ---------------------------------------------------------------
s = m:section(NamedSection, "protocols", "ndpi_protocols",
    translate("Miscellaneous Protocols"),
    translate("Other application and transport protocols."))
s.addremove = false

add_proto(s, "CORBA", "CORBA")
add_proto(s, "FIX", "FIX (Financial)")
add_proto(s, "SBE", "SBE (Simple Binary Encoding)")
add_proto(s, "FLUTE", "FLUTE/ALC")
add_proto(s, "KCP", "KCP")
add_proto(s, "RTPS", "RTPS (DDS)")
add_proto(s, "RAFT", "Raft (Consensus)")
add_proto(s, "RX", "RX (AFS)")
add_proto(s, "JRMI", "Java RMI")
add_proto(s, "AJP", "AJP (Apache JServ)")
add_proto(s, "JSON", "JSON")
add_proto(s, "ADOBE_CONNECT", "Adobe Connect")
add_proto(s, "CRYNET", "CryNet (CryEngine)")
add_proto(s, "EGD", "EGD (Entropy)")
add_proto(s, "RMCP", "RMCP (IPMI)")
add_proto(s, "SAP", "SAP")
add_proto(s, "HCL_NOTES", "HCL Notes")
add_proto(s, "OCS", "OCS Inventory")
add_proto(s, "TRUPHONE", "Truphone")
add_proto(s, "YOJIMBO", "Yojimbo")
add_proto(s, "ZUG", "ZUG")
add_proto(s, "NVIDIA", "NVIDIA")
add_proto(s, "1KXUN", "1KXUN")
add_proto(s, "SD_RTN", "SD-RTN (Agora)")
add_proto(s, "HPVIRTGRP", "HP Virtual Group")
add_proto(s, "NETMOTION", "NetMotion")
add_proto(s, "UNKNOWN", "Unknown/Unclassified")

-- ---------------------------------------------------------------
-- Inject JS for multi-column protocol layout
-- ---------------------------------------------------------------
local js = m:section(SimpleSection)
js.template = "cbi/nullsection"
js.addremove = false

local script = js:option(DummyValue, "_columns_js")
script.rawhtml = true
script.default = [[<script type="text/javascript">
(function(){
    /* Find every CBI section-node that contains protocol checkboxes */
    var nodes = document.querySelectorAll('.cbi-section-node');
    for (var i = 0; i < nodes.length; i++) {
        var proto = nodes[i].querySelector('.cbi-value[id*="-proto_"]');
        if (proto) {
            nodes[i].classList.add('ndpi-proto-columns');
        }
    }
})();
</script>]]

return m
