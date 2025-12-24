# hk kernel Makefile

TARGET = x86_64-unknown-none
KERNEL = target/$(TARGET)/release/kernel
KERNEL_DEBUG = target/$(TARGET)/debug/kernel

# ARM64 target
TARGET_ARM = aarch64-unknown-none
KERNEL_ARM = target/$(TARGET_ARM)/release/kernel

# VFAT test image settings
VFAT_IMAGE = target/vfat.img
VFAT_SIZE_KB = 1024

# EXT4 root filesystem image settings
EXT4_IMAGE = target/ext4-root.img
EXT4_SIZE_MB = 16
EXT4_ROOT_DIR = target/ext4-root

.PHONY: all build debug user iso iso-debug iso-ext4 run run-debug run-ext4 test check check-ext4 clean info help vfat-image ext4-image
.PHONY: build-arm run-arm check-arm user-arm

# Default: build everything (kernel, user binaries, ISO)
all: iso

help:
	@echo "hk kernel Makefile targets:"
	@echo ""
	@echo "  make          - Build kernel, user binaries, and ISO (default)"
	@echo "  make build    - Build kernel (release)"
	@echo "  make debug    - Build kernel (debug)"
	@echo "  make user     - Build userspace binaries and initramfs"
	@echo "  make iso      - Build bootable ISO image"
	@echo "  make iso-debug- Build bootable ISO with debug kernel"
	@echo "  make iso-ext4 - Build bootable ISO with ext4 root"
	@echo "  make ext4-image - Create ext4 root filesystem image"
	@echo ""
	@echo "  make run      - Run kernel in QEMU"
	@echo "  make run-debug- Run debug kernel in QEMU (no reboot on crash)"
	@echo "  make run-ext4 - Run kernel with ext4 root in QEMU"
	@echo ""
	@echo "  make test     - Run cargo tests (host)"
	@echo "  make check    - Boot kernel in QEMU, verify tests pass"
	@echo "  make check-ext4 - Boot kernel with ext4 root, verify tests pass"
	@echo ""
	@echo "  make build-arm - Build ARM64 kernel"
	@echo "  make run-arm   - Run ARM64 kernel in QEMU"
	@echo "  make check-arm - Boot ARM64 kernel, verify tests pass"
	@echo ""
	@echo "  make clean    - Remove all build artifacts"
	@echo "  make info     - Show kernel binary info"

build:
	cargo build -p hk-kernel --target $(TARGET) --release

debug:
	cargo build -p hk-kernel --target $(TARGET)

user:
	$(MAKE) -C user

# Create a small FAT32 test image with test files
# Requires: dosfstools (mkfs.vfat), mtools (mcopy, mmd)
vfat-image:
	@mkdir -p target
	@dd if=/dev/zero of=$(VFAT_IMAGE) bs=1K count=$(VFAT_SIZE_KB) 2>/dev/null
	@mkfs.vfat -F 32 -n "VFAT_TEST" $(VFAT_IMAGE) >/dev/null
	@echo "Hello from FAT32!" | mcopy -i $(VFAT_IMAGE) - ::HELLO.TXT
	@mmd -i $(VFAT_IMAGE) ::TESTDIR
	@echo "Nested file content" | mcopy -i $(VFAT_IMAGE) - ::TESTDIR/NESTED.TXT
	@echo "Created $(VFAT_IMAGE) with test files"

# Create an ext4 root filesystem image with proper directory structure
# Requires: e2fsprogs (mkfs.ext4)
ext4-image:
	@mkdir -p $(EXT4_ROOT_DIR)/dev
	@mkdir -p $(EXT4_ROOT_DIR)/proc
	@mkdir -p $(EXT4_ROOT_DIR)/bin
	@mkdir -p $(EXT4_ROOT_DIR)/sbin
	@mkdir -p $(EXT4_ROOT_DIR)/tmp
	@mkdir -p $(EXT4_ROOT_DIR)/sys
	@mkdir -p $(EXT4_ROOT_DIR)/etc
	@mkdir -p $(EXT4_ROOT_DIR)/home
	@mkdir -p $(EXT4_ROOT_DIR)/root
	@mkdir -p $(EXT4_ROOT_DIR)/var
	@mkdir -p $(EXT4_ROOT_DIR)/usr/bin
	@mkdir -p $(EXT4_ROOT_DIR)/usr/sbin
	@# Ensure busybox is available
	@if [ ! -f target/downloads/busybox ]; then \
		echo "Downloading busybox..."; \
		mkdir -p target/downloads; \
		apt-get install -y -qq busybox-static >/dev/null 2>&1; \
		cp /bin/busybox target/downloads/busybox; \
	fi
	@# Copy busybox to /bin
	@cp target/downloads/busybox $(EXT4_ROOT_DIR)/bin/busybox
	@chmod +x $(EXT4_ROOT_DIR)/bin/busybox
	@# Copy busybox as init (no symlink - ext4 doesn't support symlinks yet)
	@cp target/downloads/busybox $(EXT4_ROOT_DIR)/bin/init
	@chmod +x $(EXT4_ROOT_DIR)/bin/init
	@# Copy busybox as sh (no symlink - ext4 doesn't support symlinks yet)
	@cp target/downloads/busybox $(EXT4_ROOT_DIR)/bin/sh
	@chmod +x $(EXT4_ROOT_DIR)/bin/sh
	@cp target/downloads/busybox $(EXT4_ROOT_DIR)/bin/ash
	@chmod +x $(EXT4_ROOT_DIR)/bin/ash
	@# TODO: Add more utilities when ext4 symlink support is implemented
	@# For now, shell can use busybox directly via: busybox ls, busybox cat, etc.
	@# Create /etc/inittab for busybox init
	@echo '::sysinit:/bin/sh' > $(EXT4_ROOT_DIR)/etc/inittab
	@echo '::respawn:/bin/sh' >> $(EXT4_ROOT_DIR)/etc/inittab
	@echo '::ctrlaltdel:/bin/reboot' >> $(EXT4_ROOT_DIR)/etc/inittab
	@echo '::shutdown:/bin/umount -a -r' >> $(EXT4_ROOT_DIR)/etc/inittab
	@echo "Creating $(EXT4_IMAGE) ($(EXT4_SIZE_MB)MB) from $(EXT4_ROOT_DIR)..."
	@dd if=/dev/zero of=$(EXT4_IMAGE) bs=1M count=$(EXT4_SIZE_MB) 2>/dev/null
	@mkfs.ext4 -q -L "HK_ROOT" -d $(EXT4_ROOT_DIR) $(EXT4_IMAGE)
	@echo "Created $(EXT4_IMAGE) with busybox shell and utilities"

iso: build user vfat-image
	@mkdir -p target/iso/boot/grub
	@cp $(KERNEL) target/iso/boot/kernel
	@cp user/initramfs-x86_64.cpio target/iso/boot/initramfs.cpio
	@cp $(VFAT_IMAGE) target/iso/boot/vfat.img
	@cp boot/grub.cfg target/iso/boot/grub/grub.cfg
	@grub-mkrescue -o target/hk-x86_64.iso target/iso 2>/dev/null

iso-debug: debug user vfat-image
	@mkdir -p target/iso/boot/grub
	@cp $(KERNEL_DEBUG) target/iso/boot/kernel
	@cp user/initramfs-x86_64.cpio target/iso/boot/initramfs.cpio
	@cp $(VFAT_IMAGE) target/iso/boot/vfat.img
	@cp boot/grub.cfg target/iso/boot/grub/grub.cfg
	@grub-mkrescue -o target/hk-x86_64.iso target/iso 2>/dev/null

iso-ext4: build user ext4-image vfat-image
	@mkdir -p target/iso/boot/grub
	@cp $(KERNEL) target/iso/boot/kernel
	@cp user/initramfs-x86_64.cpio target/iso/boot/initramfs.cpio
	@cp $(VFAT_IMAGE) target/iso/boot/vfat.img
	@cp boot/grub-ext4.cfg target/iso/boot/grub/grub.cfg
	@grub-mkrescue -o target/hk-x86_64.iso target/iso 2>/dev/null

run: iso
	@if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then \
		echo "QEMU not found. Install with: sudo apt install qemu-system-x86"; \
		exit 1; \
	fi
	./run-qemu.sh

run-debug: iso-debug
	@if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then \
		echo "QEMU not found. Install with: sudo apt install qemu-system-x86"; \
		exit 1; \
	fi
	./run-qemu.sh -d

test:
	cargo test --all

check: iso
	@rm -f /tmp/qemu_serial.log
	@echo "Running boot test (30 second timeout)..."
	@./run-qemu.sh -t -T 30
	@if [ ! -f /tmp/qemu_serial.log ]; then \
		echo "Boot test FAILED - QEMU did not create serial log"; \
		exit 1; \
	elif grep -q "Powering off" /tmp/qemu_serial.log; then \
		echo "Boot test PASSED"; \
	else \
		echo "Boot test FAILED - 'Powering off' not found in serial log:"; \
		cat /tmp/qemu_serial.log; \
		exit 1; \
	fi

run-ext4: iso-ext4
	@if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then \
		echo "QEMU not found. Install with: sudo apt install qemu-system-x86"; \
		exit 1; \
	fi
	./run-qemu.sh --ext4-root

check-ext4: iso-ext4
	@rm -f /tmp/qemu_serial.log
	@echo "Running ext4 root boot test (30 second timeout)..."
	@./run-qemu.sh --ext4-root -t -T 30
	@if [ ! -f /tmp/qemu_serial.log ]; then \
		echo "Boot test FAILED - QEMU did not create serial log"; \
		exit 1; \
	elif grep -q "Powering off" /tmp/qemu_serial.log; then \
		echo "Boot test PASSED (ext4 root)"; \
	else \
		echo "Boot test FAILED - 'Powering off' not found in serial log:"; \
		cat /tmp/qemu_serial.log; \
		exit 1; \
	fi

clean:
	cargo clean
	$(MAKE) -C user clean

info: build
	@echo "Kernel: $(KERNEL)"
	@ls -la $(KERNEL)
	@file $(KERNEL)

# ============================================================================
# ARM64 (AArch64) targets
# ============================================================================

user-arm:
	$(MAKE) -C user ARCH=aarch64

build-arm: user-arm
	cargo build -p hk-kernel --target $(TARGET_ARM) --release

run-arm: build-arm
	./run-qemu.sh --arch arm

check-arm: build-arm
	@rm -f /tmp/qemu_serial_arm.log
	@echo "Running ARM boot test (30 second timeout)..."
	@./run-qemu.sh --arch arm -t -T 30
	@if [ ! -f /tmp/qemu_serial_arm.log ]; then \
		echo "ARM Boot test FAILED - QEMU did not create serial log"; \
		exit 1; \
	elif grep -q "Powering off" /tmp/qemu_serial_arm.log; then \
		echo "ARM Boot test PASSED"; \
	else \
		echo "ARM Boot test FAILED - 'Powering off' not found in serial log:"; \
		cat /tmp/qemu_serial_arm.log; \
		exit 1; \
	fi

info-arm: build-arm
	@echo "ARM Kernel: $(KERNEL_ARM)"
	@ls -la $(KERNEL_ARM)
	@file $(KERNEL_ARM)
