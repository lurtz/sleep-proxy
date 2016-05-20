# Copyright (C) 2014  Lutz Reinhardt
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

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
  DEPENDS:=+libstdcpp +libpthread +libpcap +ip +iptables +ip6tables +ndisc6
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
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/watchHost $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/emulateHost $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/waker $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/libsleep-proxy.so $(1)/usr/lib/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/config/watchHost.conf $(1)/etc/
	$(CP) files/watchHost.init $(1)/etc/init.d/watchHost
endef

$(eval $(call BuildPackage,sleep-proxy))
