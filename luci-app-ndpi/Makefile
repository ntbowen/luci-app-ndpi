# SPDX-License-Identifier: GPL-2.0-or-later
#
# LuCI web interface for nDPI Deep Packet Inspection
# Uses standard package.mk (NOT luci.mk) to avoid provider-hash
# constraints that make cross-build packages uninstallable.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-ndpi
PKG_VERSION:=1.0.0
PKG_RELEASE:=2
PKG_MAINTAINER:=Spark Secure <alan@spark-secure.com>
PKG_LICENSE:=GPL-2.0-or-later

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-ndpi
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=LuCI interface for nDPI DPI Firewall
  # APK v3 uses "noarch" for architecture-independent packages.  Current
  # OpenWrt maps PKGARCH:=all to noarch, but declaring it explicitly also
  # keeps this package compatible with older/custom APK packaging helpers.
  PKGARCH:=noarch
  DEPENDS:=+luci-base +luci-compat +rpcd +jshn +ndpi-tools
endef

define Package/luci-app-ndpi/description
  Web-based management interface for nDPI deep packet inspection,
  featuring real-time traffic analysis, protocol detection, flow monitoring,
  and firewall rule management via an ntopng-like dashboard.
endef

define Package/luci-app-ndpi/conffiles
/etc/config/ndpi
endef

define Build/Compile
endef

define Package/luci-app-ndpi/install
	# LuCI menu and ACL definitions
	$(INSTALL_DIR) $(1)/usr/share/luci/menu.d
	$(INSTALL_DATA) ./root/usr/share/luci/menu.d/luci-app-ndpi.json $(1)/usr/share/luci/menu.d/
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) ./root/usr/share/rpcd/acl.d/luci-app-ndpi.json $(1)/usr/share/rpcd/acl.d/

	# rpcd backend script
	$(INSTALL_DIR) $(1)/usr/libexec/rpcd
	$(INSTALL_BIN) ./root/usr/libexec/rpcd/ndpi $(1)/usr/libexec/rpcd/

	# UCI config defaults and init script
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./root/etc/config/ndpi $(1)/etc/config/
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./root/etc/uci-defaults/40_luci-ndpi $(1)/etc/uci-defaults/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./root/etc/init.d/ndpi $(1)/etc/init.d/

	# LuCI Lua controller and models (CBI)
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller
	$(INSTALL_DATA) ./luasrc/controller/ndpi.lua $(1)/usr/lib/lua/luci/controller/
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/model/cbi/ndpi
	$(INSTALL_DATA) ./luasrc/model/cbi/ndpi/*.lua $(1)/usr/lib/lua/luci/model/cbi/ndpi/
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/view/ndpi
	$(INSTALL_DATA) ./luasrc/view/ndpi/*.htm $(1)/usr/lib/lua/luci/view/ndpi/

	# Static web assets (CSS / JS)
	$(INSTALL_DIR) $(1)/www/luci-static/ndpi/css
	$(INSTALL_DATA) ./htdocs/luci-static/ndpi/css/*.css $(1)/www/luci-static/ndpi/css/
	$(INSTALL_DIR) $(1)/www/luci-static/ndpi/js
	$(INSTALL_DATA) ./htdocs/luci-static/ndpi/js/*.js $(1)/www/luci-static/ndpi/js/
endef

$(eval $(call BuildPackage,luci-app-ndpi))
