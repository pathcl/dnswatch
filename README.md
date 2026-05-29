# dnswatch

XDP-based DNS capture and threat detection for a LAN resolver.

Attaches to a network interface at driver level, captures all DNS traffic with near-zero overhead, and feeds a detection pipeline that identifies malware beaconing, DGA domains, DNS tunneling, and spyware by analyzing query patterns per client.

---

## How it works

Every DNS query from every device on the LAN transits the router's interface. `dnswatch` observes all of it without modifying the resolver (`dnsmasq`, `unbound`, etc.) and without dropping any packets.

```
NIC (enp2s0)
  └─ XDP program (kernel)       filters UDP 53, copies payload to ring buffer
       └─ ring buffer
            └─ capture (Go)     reads raw bytes, forwards to parser
                 └─ parser      DNS wire format → structured DNSPacket
                      └─ analyzer (Phase 2)   per-client state, detection rules
                           └─ alert (Phase 2) structured output / webhook
```

### XDP program — `bpf/dns_capture.c`

Runs inside the kernel at the NIC driver level, before the kernel network stack processes anything. For every packet:

1. Parses ethernet → IP → UDP headers, discards anything that is not UDP port 53
2. Copies up to 512 bytes of raw DNS payload into a BPF ring buffer alongside source IP, destination IP, ports, and a query/response flag
3. Returns `XDP_PASS` — every packet continues normally, nothing is dropped or modified

DNS payload parsing is deferred to userspace to avoid BPF verifier complexity with variable-length label loops.

### Capture — `internal/capture/`

Loads the compiled `.o` file into the kernel via `cilium/ebpf`, attaches it to the target interface, and reads events from the ring buffer in a loop. On `SIGINT`/`SIGTERM` it detaches XDP and frees BPF maps cleanly.

### Parser — `internal/parser/`

Decodes raw ring buffer bytes back into a Go struct (field layout matches the C struct exactly), then uses `miekg/dns` to unpack the DNS wire format — labels, record types, RDATA, response codes — into a typed `DNSPacket`.

---

## Requirements

- Linux kernel 6.8+ (tested on 6.12)
- NIC with native XDP support (`igb`, `i40e`, `mlx5`, `ixgbe`, `virtio_net`); generic mode works on other drivers
- Root / `CAP_NET_ADMIN`
- `clang`, `llvm`, `libbpf-dev`, `linux-headers-$(uname -r)`

```bash
apt install -y clang llvm libbpf-dev linux-headers-$(uname -r)
```

### Verify your NIC supports XDP

```bash
# check driver
for iface in $(ls /sys/class/net | grep -v lo); do
  driver=$(readlink /sys/class/net/$iface/device/driver 2>/dev/null | xargs basename 2>/dev/null)
  echo "$iface → ${driver:-virtual}"
done

# check kernel config
grep -E "^CONFIG_(BPF|XDP)" /boot/config-$(uname -r)
```

---

## Build

```bash
make        # compiles bpf/dns_capture.c → .o, then the Go binary
```

Or separately:

```bash
make bpf    # clang → bpf/dns_capture.o
make build  # go build → ./dnswatch
```

---

## Run

```bash
make run                      # attaches to enp2s0 (default)
make run IFACE=eth0           # different interface
sudo ./dnswatch -iface enp2s0
```

The compiled BPF object is embedded into the binary at build time. Copy the binary anywhere and run it — no `.o` file needed alongside it.

Must run as root. Output is one JSON object per DNS packet on stdout:

```json
{"SrcIP":"192.168.1.42","DstIP":"192.168.1.1","SrcPort":51423,"DstPort":53,"IsResponse":false,"TransactionID":12345,"Questions":["example.com."],"Answers":null,"RCode":0,"QType":1}
{"SrcIP":"192.168.1.1","DstIP":"192.168.1.42","SrcPort":53,"DstPort":51423,"IsResponse":true,"TransactionID":12345,"Questions":["example.com."],"Answers":["example.com. 3600 IN A 93.184.216.34"],"RCode":0,"QType":1}
```

---

## Key design decisions

| Decision | Reason |
|---|---|
| XDP over `AF_PACKET` / tcpdump | Driver-level hook, no kernel stack overhead |
| Ring buffer over perf event array | Single buffer, no per-CPU complexity, no loss under backpressure |
| DNS parsing in Go, not eBPF | BPF verifier rejects unbounded loops; DNS label parsing requires them |
| 512-byte payload cap | RFC 1035 UDP limit; QNAME always fits in the first bytes |
| `XDP_PASS` always (Phase 1) | Observe-only; dropping and sinkholing come in Phase 2 |

---

## Detection (Phase 2 — in progress)

Per-client state tracked in the analyzer:

| Signal | Threat |
|---|---|
| Query rate (sliding window) | Beaconing rhythm |
| QNAME entropy score | DGA (domain generation algorithm) |
| NXDOMAIN ratio | DGA (most generated domains do not resolve) |
| Subdomain cardinality per parent | DNS tunneling |
| Query type distribution (TXT/NULL spikes) | DNS tunneling |
| First-seen domain age | C2 infrastructure (newly registered domains) |

### What it will not catch

- **DoH/DoT to external resolvers** — encrypted DNS bypasses this resolver entirely. Mitigate by firewalling outbound UDP/TCP 53 and 853 to anything except your router.
- **HTTPS-based C2** — DNS still reveals the domain name but not the payload.
- **Localhost resolvers** — traffic that never leaves the querying host.

---

## Project structure

```
dnswatch/
├── bpf/
│   └── dns_capture.c        XDP program (C, compiled to BPF bytecode)
├── cmd/dnswatch/
│   └── main.go              entry point
├── internal/
│   ├── capture/             BPF loader, ring buffer reader
│   ├── parser/              DNS wire format → DNSPacket
│   ├── analyzer/            per-client state, detection rules (Phase 2)
│   └── alert/               output formatting, webhooks (Phase 2)
├── Makefile
└── go.mod
```
