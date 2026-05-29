package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/pathcl/dnswatch/internal/capture"
	"github.com/pathcl/dnswatch/internal/parser"
)

func main() {
	iface := flag.String("iface", "enp2s0", "network interface to attach XDP to")
	flag.Parse()

	if os.Getuid() != 0 {
		log.Fatal("dnswatch must run as root (XDP requires CAP_NET_ADMIN)")
	}

	packets := make(chan *parser.DNSPacket, 256)

	// Print every packet as JSON to stdout.
	// Phase 2 will replace this with the analyzer.
	go func() {
		enc := json.NewEncoder(os.Stdout)
		for pkt := range packets {
			if err := enc.Encode(pkt); err != nil {
				fmt.Fprintf(os.Stderr, "encode: %v\n", err)
			}
		}
	}()

	if err := capture.Run(*iface, packets); err != nil {
		log.Fatalf("capture: %v", err)
	}
}
