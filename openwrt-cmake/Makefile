include $(TOPDIR)/rules.mk

PKG_NAME:=sleep-proxy
PKG_VERSION:=0.0.1
PKG_RELEASE:=1
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=git@bitbucket.org:cg2/sleep-proxy.git
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_VERSION:=HEAD
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/sleep-proxy
  SECTION:=net
  CATEGORY:=Network
  DEFAULT:=m
  TITLE:=Sleep Proxy
  URL:=https://bitbucket.org/cg2/sleep-proxy
  DEPENDS:=+libstdcpp +libpthread +libpcap +ip +iptables +ip6tables +iputils-arping
endef

define Package/sleep-proxy/description
 Sleep Proxy
 Wakes a sleeping host via WOL if some client tries to connect to it.
 Servers can go into standby and save power without client side support
 with custom WOL scripts.
endef

define Package/sleep-proxy/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/watchHost $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/emulateHost $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/waker $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/libsleep-proxy.so $(1)/usr/lib/
endef

$(eval $(call BuildPackage,sleep-proxy))
