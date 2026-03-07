# Build eBPF object and EDR client. Requires: clang, llvm, linux-headers, Go.
# Debian/Kali: apt install clang llvm linux-headers-$(uname -r) golang-go

KERNEL_HEADERS ?= /lib/modules/$(shell uname -r)/build
BPF_INC        ?= $(KERNEL_HEADERS)/tools/lib
ARCH           ?= $(shell uname -m)
CLANG         ?= clang
LLC           ?= llc

# x86_64 -> x86 for kernel arch and bpf target
KERNEL_ARCH_x86_64 := x86
KERNEL_ARCH        := $(KERNEL_ARCH_$(ARCH))
KERNEL_ARCH        := $(or $(KERNEL_ARCH),$(ARCH))
BPF_ARCH_x86_64    := x86
BPF_ARCH           := $(BPF_ARCH_$(ARCH))
BPF_ARCH           := $(or $(BPF_ARCH),$(ARCH))

# BPF sources only use libbpf headers (<bpf/bpf_helpers.h>, <linux/bpf.h>).
# No kernel source tree required — libbpf-dev provides all needed headers.
SYS_ARCH_INC ?= /usr/include/$(ARCH)-linux-gnu
BPF_CFLAGS  := -O2 -g -target bpf -D__TARGET_ARCH_$(BPF_ARCH) \
	-I $(SYS_ARCH_INC) \
	-I /usr/include \
	-I $(CURDIR)/bpf/include \
	-Wno-address-of-packed-member

DIST_DIR      ?= dist
OS            ?= linux

.PHONY: all clean bpf go run fetch-gtfobins package package-deb package-rpm

all: bpf go

bpf: bpf/execve.o bpf/file_events.o bpf/network_events.o bpf/privilege_events.o bpf/exit_events.o bpf/write_events.o bpf/module_events.o bpf/process_events.o

bpf/execve.o: bpf/execve.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

bpf/file_events.o: bpf/file_events.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

bpf/network_events.o: bpf/network_events.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

bpf/privilege_events.o: bpf/privilege_events.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

bpf/exit_events.o: bpf/exit_events.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

bpf/write_events.o: bpf/write_events.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

bpf/module_events.o: bpf/module_events.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

bpf/process_events.o: bpf/process_events.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

VERSION ?= $(shell cat VERSION 2>/dev/null || echo "0.1.0")

go:
	go build -ldflags "-X main.version=$(VERSION)" -o bin/edr-client ./cmd/edr-client

run: all
	sudo ./bin/edr-client

fetch-gtfobins:
	@sh "$(CURDIR)/contrib/scripts/fetch_gtfobins.sh"

## ── Packaging (requires nFPM: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest) ──

# Build both .deb and .rpm
package: all package-deb package-rpm

package-deb: all
	mkdir -p $(DIST_DIR)
	VERSION=$(VERSION) nfpm package --config nfpm.yaml --packager deb --target $(DIST_DIR)/

package-rpm: all
	mkdir -p $(DIST_DIR)
	VERSION=$(VERSION) nfpm package --config nfpm.yaml --packager rpm --target $(DIST_DIR)/

# Build a plain tarball (distro-agnostic, used by install.sh)
package-tar: all
	mkdir -p $(DIST_DIR)
	tar -czf $(DIST_DIR)/edr-client_$(VERSION)_$(ARCH).tar.gz \
		bin/edr-client \
		bpf/*.o \
		deploy/edr-client.service \
		deploy/edr.yaml.example \
		deploy/scripts/postinstall.sh \
		deploy/scripts/preremove.sh
	@echo "Tarball: $(DIST_DIR)/edr-client_$(VERSION)_$(ARCH).tar.gz"

clean:
	rm -f bpf/execve.o bpf/file_events.o bpf/network_events.o bpf/privilege_events.o bpf/exit_events.o bpf/write_events.o bpf/module_events.o bpf/process_events.o bin/edr-client
	rm -rf $(DIST_DIR)
