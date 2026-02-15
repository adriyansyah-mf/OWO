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

# Kernel arch paths first (asm/types.h); then system linux/bpf.h; arch triplet for asm/bitsperlong.h
SYS_ARCH_INC ?= /usr/include/$(ARCH)-linux-gnu
BPF_CFLAGS  := -O2 -g -target bpf -D__TARGET_ARCH_$(BPF_ARCH) \
	-I $(KERNEL_HEADERS)/arch/$(KERNEL_ARCH)/include \
	-I $(KERNEL_HEADERS)/arch/$(KERNEL_ARCH)/include/uapi \
	-I $(KERNEL_HEADERS)/arch/$(KERNEL_ARCH)/include/generated/uapi \
	-I $(KERNEL_HEADERS)/include \
	-I $(KERNEL_HEADERS)/include/uapi \
	-I $(KERNEL_HEADERS)/include/generated/uapi \
	-I $(SYS_ARCH_INC) \
	-I $(CURDIR)/bpf/include \
	-Wno-address-of-packed-member

.PHONY: all clean bpf go run

all: bpf go

bpf: bpf/execve.o bpf/file_events.o bpf/network_events.o

bpf/execve.o: bpf/execve.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

bpf/file_events.o: bpf/file_events.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

bpf/network_events.o: bpf/network_events.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

go:
	go build -o bin/edr-client ./cmd/edr-client

run: all
	sudo ./bin/edr-client

clean:
	rm -f bpf/execve.o bpf/file_events.o bpf/network_events.o bin/edr-client
