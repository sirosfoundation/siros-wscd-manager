# siros-wscd-manager Makefile — UniFFI binding generation & cross-compilation
#
# Targets:
#   make bindings    — generate Swift + Kotlin bindings from the host library
#   make ios         — cross-compile for iOS (aarch64-apple-ios + x86_64-apple-ios simulator)
#   make xcframework — build XCFramework from iOS static libraries
#   make android     — cross-compile for Android (arm64, armv7, x86_64)
#   make aar         — package Android AAR (requires android/ layout)
#   make clean       — remove build artifacts

CRATE_NAME := siros_wscd_manager
LIB_NAME   := lib$(CRATE_NAME)
UNAME_S    := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  HOST_LIB_EXT := dylib
else
  HOST_LIB_EXT := so
endif
VERSION    := $(shell cargo metadata --no-deps --format-version 1 | python3 -c "import sys,json; print(json.load(sys.stdin)['packages'][0]['version'])")

# Directories
BUILD_DIR      := target
BINDINGS_DIR   := bindings
SWIFT_DIR      := $(BINDINGS_DIR)/swift
KOTLIN_DIR     := $(BINDINGS_DIR)/kotlin
XCFRAMEWORK    := $(BUILD_DIR)/$(CRATE_NAME).xcframework

# iOS targets
IOS_TARGETS    := aarch64-apple-ios
IOS_SIM_TARGETS := aarch64-apple-ios-sim x86_64-apple-ios

# Android targets (via cargo-ndk)
ANDROID_TARGETS := aarch64-linux-android armv7-linux-androideabi x86_64-linux-android

# Features to include in mobile builds
FEATURES := --features plugin-softkey

.PHONY: all bindings ios android xcframework aar pom clean check-bindings

all: bindings

# ── Binding generation ───────────────────────────────────────────────

bindings: bindings-swift bindings-kotlin

bindings-swift: $(BUILD_DIR)/debug/$(LIB_NAME).$(HOST_LIB_EXT)
	@mkdir -p $(SWIFT_DIR)
	cargo run --features bindgen --bin uniffi-bindgen -- generate \
		--library $(BUILD_DIR)/debug/$(LIB_NAME).$(HOST_LIB_EXT) \
		--language swift \
		--out-dir $(SWIFT_DIR)
	@echo "Swift bindings generated in $(SWIFT_DIR)"

bindings-kotlin: $(BUILD_DIR)/debug/$(LIB_NAME).$(HOST_LIB_EXT)
	@mkdir -p $(KOTLIN_DIR)
	cargo run --features bindgen --bin uniffi-bindgen -- generate \
		--library $(BUILD_DIR)/debug/$(LIB_NAME).$(HOST_LIB_EXT) \
		--language kotlin \
		--out-dir $(KOTLIN_DIR)
	@echo "Kotlin bindings generated in $(KOTLIN_DIR)"

$(BUILD_DIR)/debug/$(LIB_NAME).$(HOST_LIB_EXT):
	cargo build --features plugin-softkey

# ── iOS cross-compilation ───────────────────────────────────────────

ios: $(foreach t,$(IOS_TARGETS) $(IOS_SIM_TARGETS),ios-$(t))

ios-%:
	cargo build --release --target $* $(FEATURES)

# ── XCFramework ─────────────────────────────────────────────────────

xcframework: ios bindings-swift
	@rm -rf $(XCFRAMEWORK)
	# Create fat simulator library
	@mkdir -p $(BUILD_DIR)/ios-sim-universal
	lipo -create \
		$(foreach t,$(IOS_SIM_TARGETS),$(BUILD_DIR)/$(t)/release/$(LIB_NAME).a) \
		-output $(BUILD_DIR)/ios-sim-universal/$(LIB_NAME).a
	# Create modulemap
	@mkdir -p $(BUILD_DIR)/Headers
	@cp $(SWIFT_DIR)/$(CRATE_NAME)FFI.h $(BUILD_DIR)/Headers/
	@echo "framework module $(CRATE_NAME)FFI { header \"$(CRATE_NAME)FFI.h\" export * }" \
		> $(BUILD_DIR)/Headers/module.modulemap
	# Build XCFramework
	xcodebuild -create-xcframework \
		-library $(BUILD_DIR)/aarch64-apple-ios/release/$(LIB_NAME).a \
		-headers $(BUILD_DIR)/Headers \
		-library $(BUILD_DIR)/ios-sim-universal/$(LIB_NAME).a \
		-headers $(BUILD_DIR)/Headers \
		-output $(XCFRAMEWORK)
	@echo "XCFramework created at $(XCFRAMEWORK)"

# ── Android cross-compilation (requires cargo-ndk) ──────────────────

android: $(foreach t,$(ANDROID_TARGETS),android-$(t))

android-%:
	cargo ndk --target $* --platform 28 -- build --release $(FEATURES)

# ── AAR packaging ───────────────────────────────────────────────────

AAR_DIR := $(BUILD_DIR)/aar

aar: android
	@mkdir -p $(AAR_DIR)/jni/arm64-v8a $(AAR_DIR)/jni/armeabi-v7a $(AAR_DIR)/jni/x86_64
	cp $(BUILD_DIR)/aarch64-linux-android/release/$(LIB_NAME).so $(AAR_DIR)/jni/arm64-v8a/
	cp $(BUILD_DIR)/armv7-linux-androideabi/release/$(LIB_NAME).so $(AAR_DIR)/jni/armeabi-v7a/
	cp $(BUILD_DIR)/x86_64-linux-android/release/$(LIB_NAME).so $(AAR_DIR)/jni/x86_64/
	@echo '<?xml version="1.0" encoding="utf-8"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.sirosfoundation.wscd"/>' \
		> $(AAR_DIR)/AndroidManifest.xml
	# The AAR only ships the native .so libraries; the UniFFI Kotlin bindings are
	# consumed as vendored source by the SDK, so an empty classes.jar (required by
	# the AAR layout) is sufficient. JNA is provided transitively via the POM.
	@mkdir -p $(BUILD_DIR)/aar-classes/META-INF
	@printf 'Manifest-Version: 1.0\n' > $(BUILD_DIR)/aar-classes/META-INF/MANIFEST.MF
	cd $(BUILD_DIR)/aar-classes && zip -qr ../aar/classes.jar .
	cd $(AAR_DIR) && zip -r ../$(CRATE_NAME)-$(VERSION).aar .
	@echo "AAR created at $(BUILD_DIR)/$(CRATE_NAME)-$(VERSION).aar"

# ── Maven POM (for publishing the AAR by coordinates) ───────────────
# The Maven artifactId is hyphenated (siros-wscd-manager), unlike the underscore
# crate/library name. Consumers resolve org.sirosfoundation:siros-wscd-manager.
MAVEN_GROUP    := org.sirosfoundation
MAVEN_ARTIFACT := siros-wscd-manager

pom:
	@mkdir -p $(BUILD_DIR)
	@printf '%s\n' \
	  '<?xml version="1.0" encoding="UTF-8"?>' \
	  '<project xmlns="http://maven.apache.org/POM/4.0.0"' \
	  '         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"' \
	  '         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">' \
	  '  <modelVersion>4.0.0</modelVersion>' \
	  '  <groupId>$(MAVEN_GROUP)</groupId>' \
	  '  <artifactId>$(MAVEN_ARTIFACT)</artifactId>' \
	  '  <version>$(VERSION)</version>' \
	  '  <packaging>aar</packaging>' \
	  '  <dependencies>' \
	  '    <dependency>' \
	  '      <groupId>net.java.dev.jna</groupId>' \
	  '      <artifactId>jna</artifactId>' \
	  '      <version>5.14.0</version>' \
	  '      <type>aar</type>' \
	  '    </dependency>' \
	  '  </dependencies>' \
	  '</project>' \
	  > $(BUILD_DIR)/$(MAVEN_ARTIFACT)-$(VERSION).pom
	@echo "POM written to $(BUILD_DIR)/$(MAVEN_ARTIFACT)-$(VERSION).pom"

# ── CI helper: verify bindings are up-to-date ───────────────────────

check-bindings: bindings
	@git diff --exit-code $(BINDINGS_DIR) || \
		(echo "ERROR: Generated bindings are out of date. Run 'make bindings' and commit." && exit 1)

# ── Clean ────────────────────────────────────────────────────────────

clean:
	cargo clean
	rm -rf $(BINDINGS_DIR) $(BUILD_DIR)/aar $(BUILD_DIR)/ios-sim-universal $(BUILD_DIR)/Headers
