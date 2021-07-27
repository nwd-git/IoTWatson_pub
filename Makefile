include $(TOPDIR)/rules.mk

PKG_NAME:=watson
PKG_RELEASE:=1
PKG_VERSION:=1.0.0

include $(INCLUDE_DIR)/package.mk

define Package/watson
	DEPENDS:=+libuci +libubus +libubox +libblobmsg-json +libwatson
	CATEGORY:=Base system
	TITLE:=watson
endef

define Package/watson/description
	IoT Watson memory data
endef

define Package/watson/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/watson $(1)/usr/bin/watson
	$(INSTALL_BIN) ./files/watson.init $(1)/etc/init.d/watson
	$(INSTALL_CONF) ./files/watson.config $(1)/etc/config/watson
endef
$(eval $(call BuildPackage,watson))
