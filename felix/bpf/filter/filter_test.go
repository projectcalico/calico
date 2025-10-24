// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build cgo

package filter

import (
	"testing"

	"github.com/google/gopacket/pcap"
)

// Test constants - these match the unexported constants in filter.go
// We duplicate them here rather than exporting them to keep the filter package's
// internal BPF constants private. These values are defined by the BPF specification
// and are unlikely to change.
const (
	testBpfClassLd  uint8 = 0x0
	testBpfClassLdx uint8 = 0x1
	testBpfClassJmp uint8 = 0x5
	testBpfClassRet uint8 = 0x6

	testBpfSizeW uint8 = 0x00 // 32-bit
	testBpfSizeH uint8 = 0x08 // 16-bit
	testBpfSizeB uint8 = 0x10 // 8-bit

	testBpfModeABS uint8 = 0x20
	testBpfModeIND uint8 = 0x40
	testBpfModeMSH uint8 = 0xa0
)

func TestMaxPacketOffset(t *testing.T) {
	tests := []struct {
		name     string
		insns    []pcap.BPFInstruction
		expected int
	}{
		{
			name:     "empty program",
			insns:    []pcap.BPFInstruction{},
			expected: 0,
		},
		{
			name: "single byte absolute load at offset 0",
			insns: []pcap.BPFInstruction{
				{Code: uint16(testBpfClassLd | testBpfModeABS | testBpfSizeB), K: 0},
			},
			expected: 1, // offset 0 + 1 byte
		},
		{
			name: "single byte absolute load at offset 10",
			insns: []pcap.BPFInstruction{
				{Code: uint16(testBpfClassLd | testBpfModeABS | testBpfSizeB), K: 10},
			},
			expected: 11, // offset 10 + 1 byte
		},
		{
			name: "16-bit absolute load at offset 12",
			insns: []pcap.BPFInstruction{
				{Code: uint16(testBpfClassLd | testBpfModeABS | testBpfSizeH), K: 12},
			},
			expected: 14, // offset 12 + 2 bytes
		},
		{
			name: "32-bit absolute load at offset 20",
			insns: []pcap.BPFInstruction{
				{Code: uint16(testBpfClassLd | testBpfModeABS | testBpfSizeW), K: 20},
			},
			expected: 24, // offset 20 + 4 bytes
		},
		{
			name: "multiple loads - highest wins",
			insns: []pcap.BPFInstruction{
				{Code: uint16(testBpfClassLd | testBpfModeABS | testBpfSizeB), K: 10}, // offset 11
				{Code: uint16(testBpfClassLd | testBpfModeABS | testBpfSizeW), K: 50}, // offset 54
				{Code: uint16(testBpfClassLd | testBpfModeABS | testBpfSizeH), K: 30}, // offset 32
			},
			expected: 54, // highest offset
		},
		{
			name: "indexed load (IND mode)",
			insns: []pcap.BPFInstruction{
				{Code: uint16(testBpfClassLd | testBpfModeIND | testBpfSizeB), K: 0},
			},
			expected: 256, // 255 (max X) + 0 + 1 byte
		},
		{
			name: "indexed load with K offset",
			insns: []pcap.BPFInstruction{
				{Code: uint16(testBpfClassLd | testBpfModeIND | testBpfSizeW), K: 10},
			},
			expected: 269, // 255 (max X) + 10 + 4 bytes
		},
		{
			name: "MSH load (IP header length)",
			insns: []pcap.BPFInstruction{
				{Code: uint16(testBpfClassLdx | testBpfModeMSH | testBpfSizeB), K: 14},
			},
			expected: 15, // offset 14 + 1 byte
		},
		{
			name: "typical Ethernet + IP filter",
			insns: []pcap.BPFInstruction{
				// Load ethertype at offset 12 (2 bytes)
				{Code: uint16(testBpfClassLd | testBpfModeABS | testBpfSizeH), K: 12},
				// Load IP protocol at offset 23 (1 byte) - after 14-byte Ethernet + 9 bytes into IP
				{Code: uint16(testBpfClassLd | testBpfModeABS | testBpfSizeB), K: 23},
				// Load destination port (2 bytes) at IP header + 2
				{Code: uint16(testBpfClassLd | testBpfModeIND | testBpfSizeH), K: 2},
			},
			expected: 259, // 255 + 2 + 2 from the IND load
		},
		{
			name: "non-load instructions ignored",
			insns: []pcap.BPFInstruction{
				{Code: uint16(testBpfClassJmp), K: 0},   // jump instruction
				{Code: uint16(testBpfClassRet), K: 100}, // return instruction
				{Code: uint16(testBpfClassLd | testBpfModeABS | testBpfSizeB), K: 5},
			},
			expected: 6, // only the load counts
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MaxPacketOffset(tt.insns)
			if result != tt.expected {
				t.Errorf("MaxPacketOffset() = %d, expected %d", result, tt.expected)
			}
		})
	}
}

func TestMaxPacketOffsetWithRealBPFFilter(t *testing.T) {
	// This test uses pcap.CompileBPFFilter which requires CGO and libpcap
	// Skip if running without proper build environment

	tests := []struct {
		name        string
		expression  string
		minExpected int // minimum expected offset
	}{
		{
			name:        "tcp port 80",
			expression:  "tcp port 80",
			minExpected: 1, // should at least read some bytes
		},
		{
			name:        "icmp",
			expression:  "icmp",
			minExpected: 1,
		},
		{
			name:        "ip dst 192.168.1.1",
			expression:  "dst host 192.168.1.1",
			minExpected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Try to compile the filter
			insns, err := pcap.CompileBPFFilter(1 /* Ethernet */, 65535, tt.expression)
			if err != nil {
				t.Skipf("Skipping test - pcap.CompileBPFFilter not available: %v", err)
				return
			}

			result := MaxPacketOffset(insns)
			if result < tt.minExpected {
				t.Errorf("MaxPacketOffset() = %d, expected at least %d for filter '%s'",
					result, tt.minExpected, tt.expression)
			}

			// Log the result for informational purposes
			t.Logf("Filter '%s' has max offset: %d bytes", tt.expression, result)
		})
	}
}
