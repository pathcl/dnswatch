// Package parser converts raw ring buffer bytes into structured DNS events.
package parser

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/miekg/dns"
)

// DNSEvent mirrors the dns_event struct in bpf/dns_capture.c.
// Field layout and sizes must match exactly — no padding differences.
type DNSEvent struct {
	SrcIP      [4]byte
	DstIP      [4]byte
	SrcPort    uint16
	DstPort    uint16
	PayloadLen uint16
	IsResponse uint8
	Pad        uint8
	Payload    [512]byte
}

// DNSPacket is the parsed, userspace-friendly representation of a DNS event.
type DNSPacket struct {
	SrcIP      net.IP
	DstIP      net.IP
	SrcPort    uint16
	DstPort    uint16
	IsResponse bool

	// Parsed DNS fields.
	TransactionID uint16
	Questions     []string // QNAME strings, e.g. "example.com."
	Answers       []string // RDATA strings for responses
	RCode         int      // response code; 0 = NOERROR, 3 = NXDOMAIN
	QType         uint16   // query type of the first question (A=1, AAAA=28, TXT=16...)
}

const eventSize = 4 + 4 + 2 + 2 + 2 + 1 + 1 + 512 // 528 bytes

// Parse converts raw ring buffer bytes into a DNSPacket.
// Returns an error if the bytes are too short or DNS parsing fails.
func Parse(raw []byte) (*DNSPacket, error) {
	if len(raw) < eventSize {
		return nil, fmt.Errorf("short event: got %d bytes, want %d", len(raw), eventSize)
	}

	// Decode fixed-size fields manually to avoid unsafe.Pointer casts.
	//
	// src_ip / dst_ip: copied from ip->saddr/daddr which the kernel stores in
	// network byte order (big-endian). net.IP expects the same, so no conversion.
	//
	// src_port / dst_port / payload_len: the XDP program stores these in host
	// byte order (little-endian on x86) — ports after bpf_ntohs(), payload_len
	// as a native C integer. Use LittleEndian to decode them.
	srcIP := net.IP(raw[0:4])
	dstIP := net.IP(raw[4:8])
	srcPort := binary.LittleEndian.Uint16(raw[8:10])
	dstPort := binary.LittleEndian.Uint16(raw[10:12])
	payloadLen := binary.LittleEndian.Uint16(raw[12:14])
	isResponse := raw[14] == 1
	// raw[15] is pad — skip

	payload := raw[16:]
	if int(payloadLen) > len(payload) {
		return nil, fmt.Errorf("payload_len %d exceeds buffer %d", payloadLen, len(payload))
	}
	payload = payload[:payloadLen]

	// Parse DNS wire format using miekg/dns.
	msg := new(dns.Msg)
	if err := msg.Unpack(payload); err != nil {
		return nil, fmt.Errorf("dns unpack: %w", err)
	}

	pkt := &DNSPacket{
		SrcIP:         srcIP,
		DstIP:         dstIP,
		SrcPort:       srcPort,
		DstPort:       dstPort,
		IsResponse:    isResponse,
		TransactionID: msg.Id,
		RCode:         msg.Rcode,
	}

	for _, q := range msg.Question {
		pkt.Questions = append(pkt.Questions, q.Name)
		pkt.QType = q.Qtype
	}

	for _, rr := range msg.Answer {
		pkt.Answers = append(pkt.Answers, rr.String())
	}

	return pkt, nil
}
