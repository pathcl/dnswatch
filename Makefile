BPF_SRC  := bpf/dns_capture.c
BPF_OBJ  := bpf/dns_capture.o
BINARY   := dnswatch
IFACE    ?= enp2s0

.PHONY: all bpf build run clean

all: bpf build

# Compile the XDP program to BPF bytecode.
# -target bpf        — emit BPF ELF, not host architecture
# -O2                — required; unoptimised BPF often fails the verifier
# -g                 — include BTF debug info (needed for bpftool inspection)
# -Wall -Wextra      — catch common mistakes in BPF C
bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	clang -O2 -g -Wall -Wextra -target bpf \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-c $< -o $@

# Build the Go userspace binary.
build:
	go build -o $(BINARY) ./cmd/dnswatch

# Run with defaults. Requires root.
run: all
	sudo ./$(BINARY) -iface $(IFACE) -bpf $(BPF_OBJ)

clean:
	rm -f $(BPF_OBJ) $(BINARY)
