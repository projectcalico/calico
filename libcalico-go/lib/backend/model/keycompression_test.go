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
	"testing"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
)

// TestCompressDecompressRoundTrip verifies that known key types round-trip
// through CompressKey/DecompressKey without data loss.
func TestCompressDecompressRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		key  Key
	}{
		{
			name: "WorkloadEndpoint/kubernetes/eth0",
			key: WorkloadEndpointKey{
				Hostname:       "node-1.example.com",
				OrchestratorID: "kubernetes",
				WorkloadID:     "default/nginx-abc123",
				EndpointID:     "eth0",
			},
		},
		{
			name: "WorkloadEndpoint/openstack",
			key: WorkloadEndpointKey{
				Hostname:       "compute-01",
				OrchestratorID: "openstack",
				WorkloadID:     "instance-12345",
				EndpointID:     "tap1234",
			},
		},
		{
			name: "WorkloadEndpoint/cni",
			key: WorkloadEndpointKey{
				Hostname:       "host-a",
				OrchestratorID: "cni",
				WorkloadID:     "container-xyz",
				EndpointID:     "eth0",
			},
		},
		{
			name: "WorkloadEndpoint/empty-looking-fields",
			key: WorkloadEndpointKey{
				Hostname:       "h",
				OrchestratorID: "o",
				WorkloadID:     "w",
				EndpointID:     "e",
			},
		},
		{
			name: "WorkloadEndpoint/long-hostname",
			key: WorkloadEndpointKey{
				Hostname:       "ip-172-31-22-123.us-west-2.compute.internal",
				OrchestratorID: "kubernetes",
				WorkloadID:     "kube-system/calico-node-abcde",
				EndpointID:     "eth0",
			},
		},
		{
			name: "WorkloadEndpoint/non-compact-chars",
			key: WorkloadEndpointKey{
				Hostname:       "node-1",
				OrchestratorID: "orch\x80id",
				WorkloadID:     "work\xffload",
				EndpointID:     "ep",
			},
		},
		{
			name: "WorkloadEndpoint/all-special-bytes",
			key: WorkloadEndpointKey{
				Hostname:       "\xFD\xFE\xFF",
				OrchestratorID: "\x00",
				WorkloadID:     "\xFD\xFD",
				EndpointID:     "\xFE",
			},
		},
		{
			name: "PolicyKey/NetworkPolicy",
			key: PolicyKey{
				Kind:      apiv3.KindNetworkPolicy,
				Namespace: "default",
				Name:      "allow-dns",
			},
		},
		{
			name: "PolicyKey/GlobalNetworkPolicy",
			key: PolicyKey{
				Kind: apiv3.KindGlobalNetworkPolicy,
				Name: "deny-all",
			},
		},
		{
			name: "PolicyKey/StagedNetworkPolicy",
			key: PolicyKey{
				Kind:      apiv3.KindStagedNetworkPolicy,
				Namespace: "production",
				Name:      "my-staged-policy",
			},
		},
		{
			name: "PolicyKey/empty-namespace",
			key: PolicyKey{
				Kind: "SomeKind",
				Name: "some-name",
			},
		},
		{
			name: "ProfileRulesKey",
			key:  ProfileRulesKey{ProfileKey: ProfileKey{Name: "kns.default"}},
		},
		{
			name: "ProfileLabelsKey",
			key:  ProfileLabelsKey{ProfileKey: ProfileKey{Name: "kns.kube-system"}},
		},
		{
			name: "HostEndpointKey",
			key: HostEndpointKey{
				Hostname:   "node-1.example.com",
				EndpointID: "eth0",
			},
		},
		{
			name: "ResourceKey/global",
			key: ResourceKey{
				Kind: apiv3.KindFelixConfiguration,
				Name: "default",
			},
		},
		{
			name: "ResourceKey/namespaced",
			key: ResourceKey{
				Kind:      apiv3.KindNetworkPolicy,
				Namespace: "default",
				Name:      "my-policy",
			},
		},
		{
			name: "NetworkSetKey",
			key:  NetworkSetKey{Name: "my-network-set"},
		},
		{
			name: "NetworkSetKey/namespaced",
			key:  NetworkSetKey{Name: "production/allowed-ips"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressed, err := CompressKey(tt.key)
			if err != nil {
				t.Fatalf("CompressKey(%v) error: %v", tt.key, err)
			}

			decompressed, err := DecompressKey(compressed)
			if err != nil {
				t.Fatalf("DecompressKey error: %v (compressed: %x)", err, compressed)
			}

			if !safeKeysEqual(tt.key, decompressed) {
				t.Fatalf("round-trip mismatch:\n  original:     %v\n  decompressed: %v", tt.key, decompressed)
			}
		})
	}
}

// TestCompressFallback verifies that unknown key types fall back to encoding
// the default path and can round-trip correctly.
func TestCompressFallback(t *testing.T) {
	fallbackKeys := []Key{
		GlobalConfigKey{Name: "LogSeverityScreen"},
		HostConfigKey{Hostname: "node-1", Name: "LogSeverityScreen"},
		ReadyFlagKey{},
		WireguardKey{NodeName: "node-1"},
		HostIPKey{Hostname: "node-1"},
		HostMetadataKey{Hostname: "node-1"},
	}

	for _, key := range fallbackKeys {
		t.Run(key.String(), func(t *testing.T) {
			compressed, err := CompressKey(key)
			if err != nil {
				t.Fatalf("CompressKey(%v) error: %v", key, err)
			}

			if compressed[0] != tagUnknown {
				t.Fatalf("expected fallback tag 0x00, got 0x%02x", compressed[0])
			}

			decompressed, err := DecompressKey(compressed)
			if err != nil {
				t.Fatalf("DecompressKey error: %v", err)
			}

			if !safeKeysEqual(key, decompressed) {
				t.Fatalf("round-trip mismatch:\n  original:     %v\n  decompressed: %v", key, decompressed)
			}
		})
	}
}

// TestCompressedSize verifies that compressed keys are smaller than the
// default path representation for common key types.
func TestCompressedSize(t *testing.T) {
	tests := []struct {
		name string
		key  Key
	}{
		{
			name: "WorkloadEndpoint/kubernetes/eth0",
			key: WorkloadEndpointKey{
				Hostname:       "ip-172-31-22-123.us-west-2.compute.internal",
				OrchestratorID: "kubernetes",
				WorkloadID:     "kube-system/calico-node-abcde",
				EndpointID:     "eth0",
			},
		},
		{
			name: "PolicyKey/NetworkPolicy",
			key: PolicyKey{
				Kind:      apiv3.KindNetworkPolicy,
				Namespace: "default",
				Name:      "allow-dns",
			},
		},
		{
			name: "ProfileRulesKey",
			key: ProfileRulesKey{ProfileKey: ProfileKey{Name: "kns.default"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, err := KeyToDefaultPath(tt.key)
			if err != nil {
				t.Fatalf("KeyToDefaultPath error: %v", err)
			}

			compressed, err := CompressKey(tt.key)
			if err != nil {
				t.Fatalf("CompressKey error: %v", err)
			}

			t.Logf("path len=%d, compressed len=%d, savings=%.0f%%",
				len(path), len(compressed), 100*(1-float64(len(compressed))/float64(len(path))))

			if len(compressed) >= len(path) {
				t.Errorf("compressed key (%d bytes) should be smaller than path (%d bytes)",
					len(compressed), len(path))
			}
		})
	}
}

// TestCompactAlphabet verifies the compact alphabet round-trips all
// expected characters and correctly identifies non-compact characters.
func TestCompactAlphabet(t *testing.T) {
	compact := "abcdefghijklmnopqrstuvwxyz0123456789-./:" +
		"_ABCDEFGHIJKLMNOPQRSTUVW"
	for i := 0; i < len(compact); i++ {
		c := compact[i]
		code := charToCompact[c]
		if code == 0xFF {
			t.Errorf("expected %q (0x%02x) to be compact, got 0xFF", string(c), c)
			continue
		}
		if compactToChar[code] != c {
			t.Errorf("compact round-trip failed for %q: code=%d, back=%q", string(c), code, string(compactToChar[code]))
		}
	}

	nonCompact := "XYZ @#$%^&*()=+[]{}|\\\"'<>?,;\t\n\r\x00\x80\xFD\xFE\xFF"
	for i := 0; i < len(nonCompact); i++ {
		c := nonCompact[i]
		if charToCompact[c] != 0xFF {
			t.Errorf("expected %q (0x%02x) to be non-compact, got code %d", string(c), c, charToCompact[c])
		}
	}
}

// TestFieldEncoding verifies field encode/decode for various strings.
func TestFieldEncoding(t *testing.T) {
	tests := []string{
		"",
		"a",
		"hello-world",
		"ip-172-31-22-123.us-west-2.compute.internal",
		"kns.default",
		"kube-system/calico-node-abcde",
		"NetworkPolicy",
		"kubernetes",
		"eth0",
		"default",
		"\x00\x01\x02\xFD\xFE\xFF",
		"abc\x80def",
		"mix-of\xFFstuff",
	}

	for _, s := range tests {
		t.Run(s, func(t *testing.T) {
			buf := encodeField(nil, s)
			decoded, n, err := decodeField(buf)
			if err != nil {
				t.Fatalf("decodeField error: %v", err)
			}
			if n != len(buf) {
				t.Fatalf("decodeField consumed %d bytes, expected %d", n, len(buf))
			}
			if decoded != s {
				t.Fatalf("round-trip failed: got %q, want %q", decoded, s)
			}
		})
	}
}

// TestDictionaryEncoding verifies that dictionary entries produce
// exactly 2 bytes and round-trip correctly.
func TestDictionaryEncoding(t *testing.T) {
	dictEntries := []string{
		"kubernetes", "eth0", "default", "k8s", "openstack", "cni",
		"NetworkPolicy", "GlobalNetworkPolicy", "StagedNetworkPolicy",
		"StagedGlobalNetworkPolicy", "StagedKubernetesNetworkPolicy",
		"FelixConfiguration",
	}

	for _, s := range dictEntries {
		t.Run(s, func(t *testing.T) {
			buf := encodeField(nil, s)
			if len(buf) != 2 {
				t.Fatalf("dictionary entry should be 2 bytes, got %d: %x", len(buf), buf)
			}
			decoded, n, err := decodeField(buf)
			if err != nil {
				t.Fatalf("decodeField error: %v", err)
			}
			if n != 2 {
				t.Fatalf("consumed %d bytes, expected 2", n)
			}
			if decoded != s {
				t.Fatalf("got %q, want %q", decoded, s)
			}
		})
	}
}

// TestDecompressErrors tests that invalid compressed data returns errors.
func TestDecompressErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"empty slice", []byte{}},
		{"unknown tag", []byte{0x80}},
		{"truncated workload missing delimiters", []byte{tagWorkloadEndpoint}},
		{"truncated policy missing delimiters", []byte{tagPolicy}},
		{"truncated host endpoint missing delimiter", []byte{tagHostEndpoint}},
		{"truncated resource global missing delimiter", []byte{tagResourceKeyGlobal}},
		{"truncated resource namespaced missing delimiters", []byte{tagResourceKeyNamespaced}},
		{"invalid dict ref", []byte{tagNetworkSet, fieldDictEntry, 0}},
		{"invalid dict ref high", []byte{tagNetworkSet, fieldDictEntry, 250}},
		{"truncated escape", []byte{tagNetworkSet, fieldEscape}},
		{"invalid compact code", []byte{tagNetworkSet, compactMax}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecompressKey(tt.data)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// TestCompressUsableAsMapKey verifies that compressed keys can be used
// as Go map keys via string conversion.
func TestCompressUsableAsMapKey(t *testing.T) {
	keys := []Key{
		WorkloadEndpointKey{Hostname: "h1", OrchestratorID: "kubernetes", WorkloadID: "w1", EndpointID: "eth0"},
		WorkloadEndpointKey{Hostname: "h2", OrchestratorID: "kubernetes", WorkloadID: "w1", EndpointID: "eth0"},
		PolicyKey{Kind: "NetworkPolicy", Namespace: "default", Name: "p1"},
		PolicyKey{Kind: "NetworkPolicy", Namespace: "default", Name: "p2"},
	}

	m := make(map[string]Key)
	for _, k := range keys {
		compressed, err := CompressKey(k)
		if err != nil {
			t.Fatalf("CompressKey error: %v", err)
		}
		m[string(compressed)] = k
	}

	if len(m) != len(keys) {
		t.Fatalf("expected %d unique map entries, got %d", len(keys), len(m))
	}

	// Verify lookup works.
	for _, k := range keys {
		compressed, _ := CompressKey(k)
		got, ok := m[string(compressed)]
		if !ok {
			t.Fatalf("compressed key not found in map for %v", k)
		}
		if !safeKeysEqual(k, got) {
			t.Fatalf("map lookup mismatch: got %v, want %v", got, k)
		}
	}
}

// FuzzCompressDecompressRoundTrip fuzzes the compression/decompression
// round-trip for WorkloadEndpointKey, the most common key type.
func FuzzCompressDecompressRoundTrip(f *testing.F) {
	f.Add("node-1", "kubernetes", "default/nginx", "eth0")
	f.Add("ip-10-0-1-5.ec2.internal", "k8s", "kube-system/coredns-abc", "eth0")
	f.Add("compute-01", "openstack", "instance-123", "tap5678")
	f.Add("host", "cni", "container", "veth1234")
	f.Add("h", "o", "w", "e")
	f.Add("", "", "", "")
	f.Add("node/with/slashes", "orch/id", "work/load", "end/point")
	f.Add("node\x80", "\xff", "work\x00load", "ep")
	f.Add("\xFD\xFE\xFF", "\xFD", "\xFE", "\xFF")

	f.Fuzz(func(t *testing.T, hostname, orch, workload, endpoint string) {
		key := WorkloadEndpointKey{
			Hostname:       hostname,
			OrchestratorID: orch,
			WorkloadID:     workload,
			EndpointID:     endpoint,
		}

		compressed, err := CompressKey(key)
		if err != nil {
			t.Fatalf("CompressKey error: %v", err)
		}

		decompressed, err := DecompressKey(compressed)
		if err != nil {
			t.Fatalf("DecompressKey error: %v (compressed: %x)", err, compressed)
		}

		got, ok := decompressed.(WorkloadEndpointKey)
		if !ok {
			t.Fatalf("expected WorkloadEndpointKey, got %T", decompressed)
		}

		if got.Hostname != hostname || got.OrchestratorID != orch ||
			got.WorkloadID != workload || got.EndpointID != endpoint {
			t.Fatalf("round-trip mismatch:\n  original:     %v\n  decompressed: %v", key, got)
		}
	})
}

// FuzzCompressDecompressPolicyRoundTrip fuzzes the compression/decompression
// for PolicyKey.
func FuzzCompressDecompressPolicyRoundTrip(f *testing.F) {
	f.Add("NetworkPolicy", "default", "allow-dns")
	f.Add("GlobalNetworkPolicy", "", "deny-all")
	f.Add("StagedNetworkPolicy", "production", "my-staged")
	f.Add("Kind", "ns", "name")
	f.Add("", "", "")
	f.Add("\xff\xfe\x00", "ns\x80", "n\xffame")
	f.Add("\xFD\xFD\xFD", "\xFE", "\xFF")

	f.Fuzz(func(t *testing.T, kind, ns, name string) {
		key := PolicyKey{Kind: kind, Namespace: ns, Name: name}

		compressed, err := CompressKey(key)
		if err != nil {
			t.Fatalf("CompressKey error: %v", err)
		}

		decompressed, err := DecompressKey(compressed)
		if err != nil {
			t.Fatalf("DecompressKey error: %v", err)
		}

		got, ok := decompressed.(PolicyKey)
		if !ok {
			t.Fatalf("expected PolicyKey, got %T", decompressed)
		}

		if got.Kind != kind || got.Namespace != ns || got.Name != name {
			t.Fatalf("round-trip mismatch:\n  original:     %v\n  decompressed: %v", key, got)
		}
	})
}

// FuzzCompressDecompressProfileRoundTrip fuzzes compression/decompression for
// ProfileRulesKey and ProfileLabelsKey.
func FuzzCompressDecompressProfileRoundTrip(f *testing.F) {
	f.Add("kns.default", true)
	f.Add("kns.kube-system", false)
	f.Add("ksa.default.my-sa", true)
	f.Add("", false)
	f.Add("profile-with-special/chars", true)
	f.Add("profile\xff\x00\xFD\xFEname", false)

	f.Fuzz(func(t *testing.T, name string, isRules bool) {
		var key Key
		if isRules {
			key = ProfileRulesKey{ProfileKey: ProfileKey{Name: name}}
		} else {
			key = ProfileLabelsKey{ProfileKey: ProfileKey{Name: name}}
		}

		compressed, err := CompressKey(key)
		if err != nil {
			t.Fatalf("CompressKey error: %v", err)
		}

		decompressed, err := DecompressKey(compressed)
		if err != nil {
			t.Fatalf("DecompressKey error: %v", err)
		}

		if !safeKeysEqual(key, decompressed) {
			t.Fatalf("round-trip mismatch:\n  original:     %v\n  decompressed: %v", key, decompressed)
		}
	})
}

// FuzzDecompressKey ensures DecompressKey does not panic on arbitrary input.
func FuzzDecompressKey(f *testing.F) {
	validKeys := []Key{
		WorkloadEndpointKey{Hostname: "h", OrchestratorID: "kubernetes", WorkloadID: "w", EndpointID: "eth0"},
		PolicyKey{Kind: "NetworkPolicy", Namespace: "default", Name: "p"},
		ProfileRulesKey{ProfileKey: ProfileKey{Name: "kns.default"}},
		ProfileLabelsKey{ProfileKey: ProfileKey{Name: "kns.default"}},
		HostEndpointKey{Hostname: "h", EndpointID: "eth0"},
		ResourceKey{Kind: apiv3.KindFelixConfiguration, Name: "default"},
		ResourceKey{Kind: apiv3.KindNetworkPolicy, Namespace: "default", Name: "p"},
		NetworkSetKey{Name: "ns"},
		ReadyFlagKey{},
	}
	for _, k := range validKeys {
		compressed, err := CompressKey(k)
		if err != nil {
			continue
		}
		f.Add(compressed)
	}
	f.Add([]byte{0})
	f.Add([]byte{255})
	f.Add([]byte{1, 2, 3})
	f.Add([]byte{0xFE})
	f.Add([]byte{0xFF})
	f.Add([]byte{0xFD})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should never panic.
		_, _ = DecompressKey(data)
	})
}

// FuzzEncodeDecodeField fuzzes the field encoding/decoding directly.
func FuzzEncodeDecodeField(f *testing.F) {
	f.Add("hello")
	f.Add("")
	f.Add("kubernetes")
	f.Add("eth0")
	f.Add("default")
	f.Add("ip-172-31-22-123.us-west-2.compute.internal")
	f.Add("NetworkPolicy")
	f.Add("\x00\x01\xFD\xFE\xFF")
	f.Add("\xFD\xFD\xFD")

	f.Fuzz(func(t *testing.T, s string) {
		buf := encodeField(nil, s)
		decoded, n, err := decodeField(buf)
		if err != nil {
			t.Fatalf("decodeField(%x) error: %v", buf, err)
		}
		if n != len(buf) {
			t.Fatalf("decodeField consumed %d bytes, expected %d", n, len(buf))
		}
		if decoded != s {
			t.Fatalf("round-trip mismatch: got %q, want %q", decoded, s)
		}
	})
}
