// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.
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

package model

import (
	"fmt"
	"runtime"
	"testing"
)

// TestCompressDecompressRoundTrip verifies that known key paths round-trip
// through CompressKeyPath/DecompressKeyPath without data loss.
func TestCompressDecompressRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		// WorkloadEndpoint — k8s+eth0 (optimised tag)
		{
			name: "WorkloadEndpoint/k8s/eth0",
			path: "/calico/v1/host/node-1.example.com/workload/kubernetes/default%2fnginx-abc123/endpoint/eth0",
		},
		{
			name: "WorkloadEndpoint/k8s/eth0/long-hostname",
			path: "/calico/v1/host/ip-172-31-22-123.us-west-2.compute.internal/workload/kubernetes/kube-system%2fcalico-node-abcde/endpoint/eth0",
		},
		// WorkloadEndpoint — general (non-k8s or non-eth0)
		{
			name: "WorkloadEndpoint/openstack",
			path: "/calico/v1/host/compute-01/workload/openstack/instance-12345/endpoint/tap1234",
		},
		{
			name: "WorkloadEndpoint/cni",
			path: "/calico/v1/host/host-a/workload/cni/container-xyz/endpoint/eth0",
		},
		{
			name: "WorkloadEndpoint/k8s/non-eth0",
			path: "/calico/v1/host/node-1/workload/kubernetes/ns%2fpod/endpoint/net1",
		},
		{
			name: "WorkloadEndpoint/escaped-fields",
			path: "/calico/v1/host/foobar/workload/open%2fstack/work%2fload/endpoint/end%2fpoint",
		},
		// PolicyKey
		{
			name: "PolicyKey/NetworkPolicy",
			path: "/calico/v1/policy/NetworkPolicy/default/allow-dns",
		},
		{
			name: "PolicyKey/GlobalNetworkPolicy",
			path: "/calico/v1/policy/GlobalNetworkPolicy//deny-all",
		},
		{
			name: "PolicyKey/StagedNetworkPolicy",
			path: "/calico/v1/policy/StagedNetworkPolicy/production/my-staged-policy",
		},
		// ProfileRulesKey
		{
			name: "ProfileRulesKey",
			path: "/calico/v1/policy/profile/kns.default/rules",
		},
		// ProfileLabelsKey
		{
			name: "ProfileLabelsKey",
			path: "/calico/v1/policy/profile/kns.kube-system/labels",
		},
		// HostEndpointKey
		{
			name: "HostEndpointKey",
			path: "/calico/v1/host/node-1.example.com/endpoint/eth0",
		},
		{
			name: "HostEndpointKey/escaped",
			path: "/calico/v1/host/foobar/endpoint/end%2fpoint",
		},
		// ResourceKey — global
		{
			name: "ResourceKey/global",
			path: "/calico/resources/v3/projectcalico.org/felixconfigurations/default",
		},
		// ResourceKey — namespaced
		{
			name: "ResourceKey/namespaced",
			path: "/calico/resources/v3/projectcalico.org/networkpolicies/default/my-policy",
		},
		// NetworkSetKey
		{
			name: "NetworkSetKey",
			path: "/calico/v1/netset/my-network-set",
		},
		// Fallback paths (unrecognised)
		{
			name: "Fallback/config",
			path: "/calico/v1/config/LogSeverityScreen",
		},
		{
			name: "Fallback/ready",
			path: "/calico/v1/Ready",
		},
		{
			name: "Fallback/host-config",
			path: "/calico/v1/host/node-1/config/LogSeverityScreen",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressed := CompressKeyPath(tt.path)

			decompressed, err := DecompressKeyPath(compressed)
			if err != nil {
				t.Fatalf("DecompressKeyPath error: %v (compressed: %x)", err, []byte(compressed))
			}

			if decompressed != tt.path {
				t.Fatalf("round-trip mismatch:\n  original:     %q\n  decompressed: %q", tt.path, decompressed)
			}
		})
	}
}

// TestK8sOptimisation verifies that the k8s+eth0 optimised tag is used
// for kubernetes/eth0 workload endpoints, saving space over the
// general workload endpoint tag.
func TestK8sOptimisation(t *testing.T) {
	k8sPath := "/calico/v1/host/node-1.example.com/workload/kubernetes/default%2fnginx/endpoint/eth0"
	genPath := "/calico/v1/host/node-1.example.com/workload/openstack/default%2fnginx/endpoint/eth0"

	k8sCompressed := CompressKeyPath(k8sPath)
	genCompressed := CompressKeyPath(genPath)

	// k8s+eth0 should use tagWorkloadEndpointK8s.
	if k8sCompressed[0] != tagWorkloadEndpointK8s {
		t.Fatalf("expected tag %d for k8s+eth0, got %d", tagWorkloadEndpointK8s, k8sCompressed[0])
	}
	// General should use tagWorkloadEndpoint.
	if genCompressed[0] != tagWorkloadEndpoint {
		t.Fatalf("expected tag %d for general, got %d", tagWorkloadEndpoint, genCompressed[0])
	}
	// k8s+eth0 should be shorter (2 fields vs 4).
	if len(k8sCompressed) >= len(genCompressed) {
		t.Errorf("k8s+eth0 (%d bytes) should be shorter than general (%d bytes)",
			len(k8sCompressed), len(genCompressed))
	}

	// Both should round-trip.
	for _, path := range []string{k8sPath, genPath} {
		got, err := DecompressKeyPath(CompressKeyPath(path))
		if err != nil {
			t.Fatalf("DecompressKeyPath error: %v", err)
		}
		if got != path {
			t.Fatalf("round-trip failed: got %q, want %q", got, path)
		}
	}
}

// TestCompressedSize verifies that compressed keys are smaller than the
// default path representation for common key types.
func TestCompressedSize(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{
			name: "WorkloadEndpoint/k8s/eth0",
			path: "/calico/v1/host/ip-172-31-22-123.us-west-2.compute.internal/workload/kubernetes/kube-system%2fcalico-node-abcde/endpoint/eth0",
		},
		{
			name: "PolicyKey/NetworkPolicy",
			path: "/calico/v1/policy/NetworkPolicy/default/allow-dns",
		},
		{
			name: "ProfileRulesKey",
			path: "/calico/v1/policy/profile/kns.default/rules",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressed := CompressKeyPath(tt.path)

			t.Logf("path len=%d, compressed len=%d, savings=%.0f%%",
				len(tt.path), len(compressed), 100*(1-float64(len(compressed))/float64(len(tt.path))))

			if len(compressed) >= len(tt.path) {
				t.Errorf("compressed key (%d bytes) should be smaller than path (%d bytes)",
					len(compressed), len(tt.path))
			}
		})
	}
}

// TestCompressUsableAsMapKey verifies that compressed keys can be used
// as Go map keys via string conversion.
func TestCompressUsableAsMapKey(t *testing.T) {
	paths := []string{
		"/calico/v1/host/h1/workload/kubernetes/w1/endpoint/eth0",
		"/calico/v1/host/h2/workload/kubernetes/w1/endpoint/eth0",
		"/calico/v1/policy/NetworkPolicy/default/p1",
		"/calico/v1/policy/NetworkPolicy/default/p2",
	}

	m := make(map[CompressedKey]string)
	for _, p := range paths {
		m[CompressKeyPath(p)] = p
	}

	if len(m) != len(paths) {
		t.Fatalf("expected %d unique map entries, got %d", len(paths), len(m))
	}

	// Verify lookup works.
	for _, p := range paths {
		got, ok := m[CompressKeyPath(p)]
		if !ok {
			t.Fatalf("compressed key not found in map for %q", p)
		}
		if got != p {
			t.Fatalf("map lookup mismatch: got %q, want %q", got, p)
		}
	}
}

// TestCompactAlphabet verifies the compact alphabet round-trips all
// expected characters and correctly identifies non-compact characters.
func TestCompactAlphabet(t *testing.T) {
	compact := "abcdefghijklmnopqrstuvwxyz-./_"
	for i := 0; i < len(compact); i++ {
		c := compact[i]
		code := charTo5Bit[c]
		if code == 0xFF {
			t.Errorf("expected %q (0x%02x) to be compact, got 0xFF", string(c), c)
			continue
		}
		if fiveBitToChar[code] != c {
			t.Errorf("compact round-trip failed for %q: code=%d, back=%q", string(c), code, string(fiveBitToChar[code]))
		}
	}

	nonCompact := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ @#$%^&*()=+[]{}|\\\"'<>?,;:\t\n\r\x00\x80\xFD\xFE\xFF"
	for i := 0; i < len(nonCompact); i++ {
		c := nonCompact[i]
		if charTo5Bit[c] != 0xFF {
			t.Errorf("expected %q (0x%02x) to be non-compact, got code %d", string(c), c, charTo5Bit[c])
		}
	}
}

// TestFieldEncoding verifies field encode/decode for various strings
// via the 5-bit packed stream.
func TestFieldEncoding(t *testing.T) {
	tests := []string{
		"",
		"a",
		"hello-world",
		"ip-172-31-22-123.us-west-2.compute.internal",
		"kns.default",
		"kube-system/calico-node-abcde",
		"networkpolicies",
		"kubernetes",
		"eth0",
		"default",
		"\x00\x01\x02\xFD\xFE\xFF",
		"abc\x80def",
		"mix-of\xFFstuff",
	}

	for _, s := range tests {
		t.Run(s, func(t *testing.T) {
			p := &bitPacker{}
			encodeField(p, s)
			p.writeCodes(codeSpecial, specialEnd)
			p.flush()

			fields, err := decodeFields(p.result())
			if err != nil {
				t.Fatalf("decodeFields error: %v", err)
			}
			if len(fields) != 1 {
				t.Fatalf("expected 1 field, got %d", len(fields))
			}
			if fields[0] != s {
				t.Fatalf("round-trip failed: got %q, want %q", fields[0], s)
			}
		})
	}
}

// TestDictionaryEncoding verifies that dictionary entries encode as
// exactly 10 bits (2 five-bit codes) plus the end marker, and
// round-trip correctly.
func TestDictionaryEncoding(t *testing.T) {
	dictEntries := []string{
		"kubernetes", "eth0", "default", "k8s", "openstack", "cni",
		"networkpolicies", "globalnetworkpolicies", "stagednetworkpolicies",
		"stagedglobalnetworkpolicies", "stagedkubernetesnetworkpolicies",
		"felixconfigurations",
	}

	for _, s := range dictEntries {
		t.Run(s, func(t *testing.T) {
			p := &bitPacker{}
			encodeField(p, s)
			p.writeCodes(codeSpecial, specialEnd)
			p.flush()
			packed := p.result()

			// Dict entry = 10 bits, end marker = 10 bits = 20 bits → 3 bytes.
			if len(packed) != 3 {
				t.Fatalf("dictionary entry + end marker should pack to 3 bytes, got %d: %x", len(packed), packed)
			}

			fields, err := decodeFields(packed)
			if err != nil {
				t.Fatalf("decodeFields error: %v", err)
			}
			if len(fields) != 1 || fields[0] != s {
				t.Fatalf("got %q, want %q", fields, []string{s})
			}
		})
	}
}

// TestDecompressErrors tests that invalid compressed data returns errors.
func TestDecompressErrors(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"empty", ""},
		{"unknown tag", "\x80"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecompressKeyPath(CompressedKey(tt.data))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// Test5BitPacking verifies that the 5-bit packer/unpacker round-trip
// sequences of codes correctly.
func Test5BitPacking(t *testing.T) {
	// Pack a known sequence and verify it unpacks correctly.
	// Include end marker to avoid padding ambiguity.
	codes := []byte{0, 1, 2, 30, 15, 7, 31, 0, 25, 26, 27, 28, 29, 31, 1}
	p := &bitPacker{}
	p.writeCodes(codes...)
	p.flush()

	u := &bitUnpacker{data: p.result()}
	for i, want := range codes {
		got := u.readCode()
		if got < 0 {
			t.Fatalf("readCode exhausted at index %d, expected %d", i, want)
		}
		if byte(got) != want {
			t.Fatalf("readCode[%d]: got %d, want %d", i, got, want)
		}
	}
}

// TestMultiFieldPackedEncoding verifies encoding/decoding multiple
// fields separated by delimiters in the 5-bit stream.
func TestMultiFieldPackedEncoding(t *testing.T) {
	fields := []string{"hello", "world", "test-field", "abc/def"}
	p := &bitPacker{}
	for i, f := range fields {
		if i > 0 {
			encodeDelimiter(p)
		}
		encodeField(p, f)
	}
	p.writeCodes(codeSpecial, specialEnd)
	p.flush()

	decoded, err := decodeFields(p.result())
	if err != nil {
		t.Fatalf("decodeFields error: %v", err)
	}
	if len(decoded) != len(fields) {
		t.Fatalf("expected %d fields, got %d: %v", len(fields), len(decoded), decoded)
	}
	for i := range fields {
		if decoded[i] != fields[i] {
			t.Fatalf("field[%d]: got %q, want %q", i, decoded[i], fields[i])
		}
	}
}

// Test5BitPackingSavings verifies that compact-only strings use
// fewer bytes when 5-bit packed than raw ASCII.
func Test5BitPackingSavings(t *testing.T) {
	typicalNames := []string{
		"ip-one-two-three.us-west.compute.internal",
		"kube-system/calico-node-abcde",
		"my-network-policy",
		"kns.default",
		"hello-world",
	}

	for _, s := range typicalNames {
		t.Run(s, func(t *testing.T) {
			p := &bitPacker{}
			encodeField(p, s)
			p.writeCodes(codeSpecial, specialEnd)
			p.flush()
			packed := p.result()

			t.Logf("string %q: raw=%d bytes, packed=%d bytes, savings=%.0f%%",
				s, len(s), len(packed), 100*(1-float64(len(packed))/float64(len(s))))

			if len(packed) >= len(s) {
				t.Errorf("5-bit packed (%d bytes) should be smaller than raw (%d bytes) for %q",
					len(packed), len(s), s)
			}
		})
	}
}

// FuzzCompressDecompressRoundTrip is a single fuzz test with an input
// corpus containing examples of all the different key path types.
// It verifies that any path round-trips correctly.
func FuzzCompressDecompressRoundTrip(f *testing.F) {
	// Workload endpoints — k8s+eth0 (optimised tag)
	f.Add("/calico/v1/host/node-1.example.com/workload/kubernetes/default%2fnginx-abc123/endpoint/eth0")
	f.Add("/calico/v1/host/ip-172-31-22-123.us-west-2.compute.internal/workload/kubernetes/kube-system%2fcalico-node-abcde/endpoint/eth0")
	// Workload endpoints — general
	f.Add("/calico/v1/host/compute-01/workload/openstack/instance-12345/endpoint/tap1234")
	f.Add("/calico/v1/host/host-a/workload/cni/container-xyz/endpoint/eth0")
	f.Add("/calico/v1/host/node-1/workload/kubernetes/ns%2fpod/endpoint/net1")
	f.Add("/calico/v1/host/foobar/workload/open%2fstack/work%2fload/endpoint/end%2fpoint")
	f.Add("/calico/v1/host/h/workload/o/w/endpoint/e")
	// Policy keys
	f.Add("/calico/v1/policy/NetworkPolicy/default/allow-dns")
	f.Add("/calico/v1/policy/GlobalNetworkPolicy//deny-all")
	f.Add("/calico/v1/policy/StagedNetworkPolicy/production/my-staged-policy")
	f.Add("/calico/v1/policy/StagedGlobalNetworkPolicy//staged-deny")
	f.Add("/calico/v1/policy/StagedKubernetesNetworkPolicy/kube-system/staged-k8s")
	// Profile keys
	f.Add("/calico/v1/policy/profile/kns.default/rules")
	f.Add("/calico/v1/policy/profile/kns.kube-system/labels")
	f.Add("/calico/v1/policy/profile/ksa.default.my-sa/rules")
	// Host endpoint keys
	f.Add("/calico/v1/host/node-1.example.com/endpoint/eth0")
	f.Add("/calico/v1/host/foobar/endpoint/end%2fpoint")
	// Resource keys
	f.Add("/calico/resources/v3/projectcalico.org/felixconfigurations/default")
	f.Add("/calico/resources/v3/projectcalico.org/networkpolicies/default/my-policy")
	// Network set keys
	f.Add("/calico/v1/netset/my-network-set")
	// Fallback paths
	f.Add("/calico/v1/config/LogSeverityScreen")
	f.Add("/calico/v1/Ready")
	f.Add("/calico/v1/host/node-1/config/LogSeverityScreen")
	f.Add("/calico/v1/host/node-1/metadata")
	f.Add("/calico/v1/host/node-1/bird_ip")
	// Pathological inputs
	f.Add("")
	f.Add("/")
	f.Add("not-a-calico-path")
	f.Add("/calico/v1/host")
	f.Add("/calico/v1/host/a/workload/b/c/endpoint")

	f.Fuzz(func(t *testing.T, path string) {
		compressed := CompressKeyPath(path)

		decompressed, err := DecompressKeyPath(compressed)
		if err != nil {
			t.Fatalf("DecompressKeyPath error: %v (compressed: %x)", err, []byte(compressed))
		}

		if decompressed != path {
			t.Fatalf("round-trip mismatch:\n  original:     %q\n  decompressed: %q", path, decompressed)
		}
	})
}

// TestExpand verifies the CompressedKey.Expand convenience method.
func TestExpand(t *testing.T) {
	paths := []string{
		"/calico/v1/host/node-1/workload/kubernetes/default%2fnginx/endpoint/eth0",
		"/calico/v1/policy/NetworkPolicy/default/allow-dns",
		"/calico/v1/policy/profile/kns.default/rules",
		"/calico/v1/config/LogSeverityScreen",
	}
	for _, path := range paths {
		ck := CompressKeyPath(path)
		got, err := ck.Expand()
		if err != nil {
			t.Fatalf("Expand error for %q: %v", path, err)
		}
		if got != path {
			t.Fatalf("Expand mismatch: got %q, want %q", got, path)
		}
	}
}

// benchmarkPaths is a representative mix of key paths for benchmarks.
var benchmarkPaths = []string{
	// Workload endpoint (k8s+eth0, the dominant case)
	"/calico/v1/host/ip-172-31-22-123.us-west-2.compute.internal/workload/kubernetes/kube-system%2fcalico-node-abcde/endpoint/eth0",
	// Workload endpoint (general)
	"/calico/v1/host/compute-01/workload/openstack/instance-12345/endpoint/tap1234",
	// Policy
	"/calico/v1/policy/NetworkPolicy/default/allow-dns",
	// Profile rules
	"/calico/v1/policy/profile/kns.default/rules",
	// Resource key (namespaced)
	"/calico/resources/v3/projectcalico.org/networkpolicies/default/my-policy",
	// Fallback
	"/calico/v1/config/LogSeverityScreen",
}

func BenchmarkCompressKeyPath(b *testing.B) {
	for _, path := range benchmarkPaths {
		b.Run(path, func(b *testing.B) {
			for b.Loop() {
				_ = CompressKeyPath(path)
			}
		})
	}
}

func BenchmarkDecompressKeyPath(b *testing.B) {
	compressed := make([]CompressedKey, len(benchmarkPaths))
	for i, p := range benchmarkPaths {
		compressed[i] = CompressKeyPath(p)
	}
	b.ResetTimer()
	for i, ck := range compressed {
		b.Run(benchmarkPaths[i], func(b *testing.B) {
			for b.Loop() {
				_, _ = DecompressKeyPath(ck)
			}
		})
	}
}

// BenchmarkMapInsertRawString measures the cost of inserting raw
// default-path strings into a map, simulating the old dedupe buffer.
func BenchmarkMapInsertRawString(b *testing.B) {
	// Generate N distinct keys with realistic patterns.
	const N = 10000
	keys := make([]string, N)
	for i := range keys {
		keys[i] = fmt.Sprintf("/calico/v1/host/node-%d/workload/kubernetes/ns%d%%2fpod-%d/endpoint/eth0", i%100, i%20, i)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		m := make(map[string]int, N)
		for i, k := range keys {
			m[k] = i
		}
	}
}

// BenchmarkMapInsertCompressedKey measures the cost of compressing
// default-path strings and inserting the CompressedKey into a map,
// simulating the new dedupe buffer.
func BenchmarkMapInsertCompressedKey(b *testing.B) {
	const N = 10000
	keys := make([]string, N)
	for i := range keys {
		keys[i] = fmt.Sprintf("/calico/v1/host/node-%d/workload/kubernetes/ns%d%%2fpod-%d/endpoint/eth0", i%100, i%20, i)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		m := make(map[CompressedKey]int, N)
		for i, k := range keys {
			m[CompressKeyPath(k)] = i
		}
	}
}

// BenchmarkMapMemory reports the approximate memory overhead of storing
// N keys in maps using raw strings vs CompressedKeys.
func BenchmarkMapMemory(b *testing.B) {
	const N = 10000
	rawKeys := make([]string, N)
	compKeys := make([]CompressedKey, N)
	for i := range rawKeys {
		rawKeys[i] = fmt.Sprintf("/calico/v1/host/node-%d/workload/kubernetes/ns%d%%2fpod-%d/endpoint/eth0", i%100, i%20, i)
		compKeys[i] = CompressKeyPath(rawKeys[i])
	}

	// Report the average key size.
	totalRaw, totalComp := 0, 0
	for i := range rawKeys {
		totalRaw += len(rawKeys[i])
		totalComp += len(compKeys[i])
	}
	b.Logf("Average raw key: %d bytes, compressed: %d bytes, savings: %.0f%%",
		totalRaw/N, totalComp/N, 100*(1-float64(totalComp)/float64(totalRaw)))

	b.Run("RawStringMap", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			m := make(map[string]int, N)
			for i, k := range rawKeys {
				m[k] = i
			}
			runtime.KeepAlive(m)
		}
	})
	b.Run("CompressedKeyMap", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			m := make(map[CompressedKey]int, N)
			for i, k := range compKeys {
				m[k] = i
			}
			runtime.KeepAlive(m)
		}
	})
}
