BPF_SRC  := bpf/dns_capture.c
# Output alongside the capture package so //go:embed can pick it up.
# go:embed does not allow '..' in paths, so the .o must live inside
# the package directory that embeds it.
BPF_OBJ  := internal/capture/dns_capture.o
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
# The compiled BPF object is embedded at build time; the binary is self-contained.
build:
	go build -o $(BINARY) ./cmd/dnswatch

# Run with defaults. Requires root.
run: all
	sudo ./$(BINARY) -iface $(IFACE)

clean:
	rm -f $(BPF_OBJ) $(BINARY)
