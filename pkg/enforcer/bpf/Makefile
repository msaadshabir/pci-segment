# Makefile for compiling eBPF programs

CLANG ?= clang
LLC ?= llc
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -O2 -g -Wall \
	-target bpf \
	-D__TARGET_ARCH_$(ARCH) \
	-I/usr/include/$(shell uname -m)-linux-gnu

BPF_SRC := pci_segment.c
BPF_OBJ := pci_segment.o

.PHONY: all clean

all: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f $(BPF_OBJ)

# For development: compile and view the LLVM IR
debug: $(BPF_SRC)
	$(CLANG) $(BPF_CFLAGS) -S -emit-llvm -c $< -o pci_segment.ll
	cat pci_segment.ll
