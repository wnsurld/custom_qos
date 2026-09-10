include $(TOPDIR)/rules.mk

PKG_NAME:=adaptive-latency
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_BUILD_DEPENDS:=libbpf libelf zlib
HOST_CLANG:=$(shell command -v clang)

include $(INCLUDE_DIR)/package.mk

define Package/adaptive-latency
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Adaptive latency protection daemon
  DEPENDS:=+libbpf +libelf +zlib +ip-full +tc-full +kmod-ifb +kmod-sched-core +kmod-sched-bpf
endef

define Package/adaptive-latency/description
  Conflict-aware download shaping for OpenWrt using TC eBPF flow observation,
  userspace classification, and IFB egress shaping.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./bpf $(PKG_BUILD_DIR)/
	$(CP) ./daemon $(PKG_BUILD_DIR)/
	$(CP) ./scripts $(PKG_BUILD_DIR)/
	$(CP) ./source.mk $(PKG_BUILD_DIR)/Makefile
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CLANG="$(CLANG)" \
		CFLAGS="$(TARGET_CFLAGS) $(TARGET_CPPFLAGS) -I$(STAGING_DIR)/usr/include -std=gnu11 -Wall -Wextra" \
		LDFLAGS="$(TARGET_LDFLAGS) -L$(STAGING_DIR)/usr/lib" \
		LDLIBS="-lbpf -lelf -lz" \
		daemon
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CLANG="$(HOST_CLANG)" \
		BPF_CFLAGS="-O2 -g -target bpf -Wall -Wextra -I$(STAGING_DIR)/usr/include -I$(TOOLCHAIN_DIR)/include" \
		bpf
endef

define Package/adaptive-latency/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/build/adaptive-latencyd $(1)/usr/sbin/adaptive-latencyd

	$(INSTALL_DIR) $(1)/usr/lib/adaptive-latency
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/build/flowmon.bpf.o $(1)/usr/lib/adaptive-latency/flowmon.bpf.o
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/scripts/init_ifb_tc.sh $(1)/usr/lib/adaptive-latency/init_ifb_tc.sh
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/scripts/cleanup_tc.sh $(1)/usr/lib/adaptive-latency/cleanup_tc.sh
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/scripts/set_bulk_rate.sh $(1)/usr/lib/adaptive-latency/set_bulk_rate.sh
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/scripts/show_tc_state.sh $(1)/usr/lib/adaptive-latency/show_tc_state.sh

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/adaptive_latency $(1)/etc/init.d/adaptive_latency

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/adaptive_latency $(1)/etc/config/adaptive_latency
endef

$(eval $(call BuildPackage,adaptive-latency))
