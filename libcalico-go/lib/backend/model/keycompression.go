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
)

// Compressed key format
// =====================
//
// Compressed keys are designed to be used directly as Go map[string]…
// keys in deduplicating buffers. The overall length is carried by the
// Go string header, so the encoding stores no explicit length fields.
//
// Layout:
//
//   [type_tag: 1 byte] [field0] [0xFE field1] [0xFE field2] …
//
// The type tag identifies the key type; fields are separated by the
// delimiter byte 0xFE.
//
// Each field is encoded character-by-character:
//
//   • Characters in the compact alphabet (a-z, 0-9, -, ., /, :, _,
//     A-W) are mapped to single bytes in the range 0x00-0x28 (0-40).
//     These dominate Kubernetes names and are stored in 1 byte each.
//
//   • Characters outside the compact alphabet are escaped:
//     [0xFD] [raw_byte]. This costs 2 bytes per rare character.
//
//   • Whole-field dictionary matches (e.g. "kubernetes", "eth0",
//     "default") are encoded as [0xFF] [dict_index] — 2 bytes total
//     regardless of the original string length.
//
// Reserved byte values within a field:
//
//   0xFD  escape prefix (next byte is a literal)
//   0xFE  field delimiter (never appears inside a field)
//   0xFF  dictionary prefix (next byte is a dictionary index)

// Key type tags — first byte of compressed keys.
const (
	tagUnknown byte = iota
	tagWorkloadEndpoint
	tagPolicy
	tagProfileRules
	tagProfileLabels
	tagHostEndpoint
	tagResourceKeyGlobal
	tagResourceKeyNamespaced
	tagNetworkSet
)

// Special bytes used within field encodings.
const (
	fieldEscape    byte = 0xFD
	fieldDelimiter byte = 0xFE
	fieldDictEntry byte = 0xFF
)

// Dictionary indices for common whole-field values.
const (
	dictKubernetes byte = iota + 1
	dictEth0
	dictDefault
	dictK8s
	dictOpenstack
	dictCNI
	dictNetworkPolicy
	dictGlobalNetworkPolicy
	dictStagedNetworkPolicy
	dictStagedGlobalNetworkPolicy
	dictStagedKubernetesNetworkPolicy
	dictFelixConfiguration
	// dictEnd is a sentinel; all valid indices are < dictEnd.
	dictEnd
)

// dictStrings maps dictionary indices to their string values.
var dictStrings [dictEnd]string

// dictLookup maps string values to their dictionary indices.
var dictLookup map[string]byte

func init() {
	dictStrings[dictKubernetes] = "kubernetes"
	dictStrings[dictEth0] = "eth0"
	dictStrings[dictDefault] = "default"
	dictStrings[dictK8s] = "k8s"
	dictStrings[dictOpenstack] = "openstack"
	dictStrings[dictCNI] = "cni"
	dictStrings[dictNetworkPolicy] = "NetworkPolicy"
	dictStrings[dictGlobalNetworkPolicy] = "GlobalNetworkPolicy"
	dictStrings[dictStagedNetworkPolicy] = "StagedNetworkPolicy"
	dictStrings[dictStagedGlobalNetworkPolicy] = "StagedGlobalNetworkPolicy"
	dictStrings[dictStagedKubernetesNetworkPolicy] = "StagedKubernetesNetworkPolicy"
	dictStrings[dictFelixConfiguration] = "FelixConfiguration"

	dictLookup = make(map[string]byte, len(dictStrings))
	for i := byte(1); i < dictEnd; i++ {
		dictLookup[dictStrings[i]] = i
	}
}

// --- Compact alphabet ---
//
// Maps the characters most common in Kubernetes resource names to
// single bytes in the range 0x00-0x28 (41 values). The remaining
// byte values up to 0xFC are unused, and 0xFD-0xFF are reserved.
//
//   0-25:  a-z
//   26-35: 0-9
//   36:    '-'
//   37:    '.'
//   38:    '/'
//   39:    ':'
//   40:    '_'
//   41-63: A-W  (23 uppercase letters; X/Y/Z are rare and escaped)

const compactMax = 64 // codes 0-63 are compact

// charToCompact maps ASCII byte values to compact codes.
// 0xFF means the character is not in the compact alphabet.
var charToCompact [256]byte

// compactToChar maps compact codes back to ASCII byte values.
var compactToChar [compactMax]byte

func init() {
	for i := range charToCompact {
		charToCompact[i] = 0xFF
	}
	code := byte(0)
	for c := byte('a'); c <= 'z'; c++ {
		charToCompact[c] = code
		compactToChar[code] = c
		code++
	}
	for c := byte('0'); c <= '9'; c++ {
		charToCompact[c] = code
		compactToChar[code] = c
		code++
	}
	for _, c := range []byte{'-', '.', '/', ':', '_'} {
		charToCompact[c] = code
		compactToChar[code] = c
		code++
	}
	for c := byte('A'); c <= 'W'; c++ {
		charToCompact[c] = code
		compactToChar[code] = c
		code++
	}
}

// --- Field encoding/decoding ---

// encodeField appends the encoded form of s to buf.
// If s matches a dictionary entry, the 2-byte dictionary form is used.
// Otherwise each character is encoded individually: compact chars as
// a single byte, others as [0xFD][raw_byte].
func encodeField(buf []byte, s string) []byte {
	if idx, ok := dictLookup[s]; ok {
		return append(buf, fieldDictEntry, idx)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if code := charToCompact[c]; code != 0xFF {
			buf = append(buf, code)
		} else {
			buf = append(buf, fieldEscape, c)
		}
	}
	return buf
}

// decodeField reads a single field from data, stopping at a
// fieldDelimiter or end-of-data. Returns the decoded string and the
// number of bytes consumed (excluding any trailing delimiter).
func decodeField(data []byte) (string, int, error) {
	if len(data) == 0 {
		return "", 0, nil
	}
	// Dictionary entry.
	if data[0] == fieldDictEntry {
		if len(data) < 2 {
			return "", 0, fmt.Errorf("truncated dictionary reference")
		}
		idx := data[1]
		if idx == 0 || idx >= dictEnd {
			return "", 0, fmt.Errorf("invalid dictionary index: %d", idx)
		}
		return dictStrings[idx], 2, nil
	}

	// Character-by-character decoding.
	var out []byte
	i := 0
	for i < len(data) {
		b := data[i]
		if b == fieldDelimiter {
			break
		}
		if b == fieldEscape {
			if i+1 >= len(data) {
				return "", 0, fmt.Errorf("truncated escape sequence")
			}
			out = append(out, data[i+1])
			i += 2
			continue
		}
		if b == fieldDictEntry {
			return "", 0, fmt.Errorf("unexpected dictionary marker mid-field")
		}
		if b >= compactMax {
			return "", 0, fmt.Errorf("invalid compact code: 0x%02x", b)
		}
		out = append(out, compactToChar[b])
		i++
	}
	return string(out), i, nil
}

// --- Public API ---

// CompressKey compresses a Key into a compact byte slice suitable for
// use as a Go map key (via string(result)). The encoding eliminates
// redundant path prefixes and uses single-byte codes for common
// characters, producing significantly shorter representations than
// the default path strings.
func CompressKey(key Key) ([]byte, error) {
	switch k := key.(type) {
	case WorkloadEndpointKey:
		return compressWorkloadEndpoint(k), nil
	case PolicyKey:
		return compressPolicy(k), nil
	case ProfileRulesKey:
		return compressProfileRules(k), nil
	case ProfileLabelsKey:
		return compressProfileLabels(k), nil
	case HostEndpointKey:
		return compressHostEndpoint(k), nil
	case ResourceKey:
		return compressResource(k), nil
	case NetworkSetKey:
		return compressNetworkSet(k), nil
	default:
		return compressFallback(key)
	}
}

// DecompressKey decompresses a byte slice produced by CompressKey back
// into a Key.
func DecompressKey(data []byte) (Key, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty compressed key")
	}
	switch data[0] {
	case tagWorkloadEndpoint:
		return decompressWorkloadEndpoint(data[1:])
	case tagPolicy:
		return decompressPolicy(data[1:])
	case tagProfileRules:
		return decompressProfileRules(data[1:])
	case tagProfileLabels:
		return decompressProfileLabels(data[1:])
	case tagHostEndpoint:
		return decompressHostEndpoint(data[1:])
	case tagResourceKeyGlobal:
		return decompressResourceGlobal(data[1:])
	case tagResourceKeyNamespaced:
		return decompressResourceNamespaced(data[1:])
	case tagNetworkSet:
		return decompressNetworkSet(data[1:])
	case tagUnknown:
		return decompressFallback(data[1:])
	default:
		return nil, fmt.Errorf("unknown key type tag: 0x%02x", data[0])
	}
}

// --- Field splitting helper ---

// nextField decodes the next field from data. If expectDelimiter is
// true, data must start with fieldDelimiter which is consumed.
// Returns the decoded string and remaining unconsumed data.
func nextField(data []byte, expectDelimiter bool) (string, []byte, error) {
	if expectDelimiter {
		if len(data) == 0 || data[0] != fieldDelimiter {
			return "", nil, fmt.Errorf("expected field delimiter")
		}
		data = data[1:]
	}
	s, n, err := decodeField(data)
	if err != nil {
		return "", nil, err
	}
	return s, data[n:], nil
}

// --- Per-type compress/decompress ---

// WorkloadEndpointKey: [tag] [hostname] 0xFE [orchestratorID] 0xFE [workloadID] 0xFE [endpointID]
func compressWorkloadEndpoint(k WorkloadEndpointKey) []byte {
	buf := make([]byte, 0, 1+len(k.Hostname)+len(k.OrchestratorID)+len(k.WorkloadID)+len(k.EndpointID)+3)
	buf = append(buf, tagWorkloadEndpoint)
	buf = encodeField(buf, k.Hostname)
	buf = append(buf, fieldDelimiter)
	buf = encodeField(buf, k.OrchestratorID)
	buf = append(buf, fieldDelimiter)
	buf = encodeField(buf, k.WorkloadID)
	buf = append(buf, fieldDelimiter)
	buf = encodeField(buf, k.EndpointID)
	return buf
}

func decompressWorkloadEndpoint(data []byte) (Key, error) {
	hostname, data, err := nextField(data, false)
	if err != nil {
		return nil, fmt.Errorf("WorkloadEndpointKey.Hostname: %w", err)
	}
	orch, data, err := nextField(data, true)
	if err != nil {
		return nil, fmt.Errorf("WorkloadEndpointKey.OrchestratorID: %w", err)
	}
	workload, data, err := nextField(data, true)
	if err != nil {
		return nil, fmt.Errorf("WorkloadEndpointKey.WorkloadID: %w", err)
	}
	endpoint, _, err := nextField(data, true)
	if err != nil {
		return nil, fmt.Errorf("WorkloadEndpointKey.EndpointID: %w", err)
	}
	return WorkloadEndpointKey{
		Hostname:       hostname,
		OrchestratorID: orch,
		WorkloadID:     workload,
		EndpointID:     endpoint,
	}, nil
}

// PolicyKey: [tag] [kind] 0xFE [namespace] 0xFE [name]
func compressPolicy(k PolicyKey) []byte {
	buf := make([]byte, 0, 1+len(k.Kind)+len(k.Namespace)+len(k.Name)+2)
	buf = append(buf, tagPolicy)
	buf = encodeField(buf, k.Kind)
	buf = append(buf, fieldDelimiter)
	buf = encodeField(buf, k.Namespace)
	buf = append(buf, fieldDelimiter)
	buf = encodeField(buf, k.Name)
	return buf
}

func decompressPolicy(data []byte) (Key, error) {
	kind, data, err := nextField(data, false)
	if err != nil {
		return nil, fmt.Errorf("PolicyKey.Kind: %w", err)
	}
	ns, data, err := nextField(data, true)
	if err != nil {
		return nil, fmt.Errorf("PolicyKey.Namespace: %w", err)
	}
	name, _, err := nextField(data, true)
	if err != nil {
		return nil, fmt.Errorf("PolicyKey.Name: %w", err)
	}
	return PolicyKey{Kind: kind, Namespace: ns, Name: name}, nil
}

// ProfileRulesKey: [tag] [name]
func compressProfileRules(k ProfileRulesKey) []byte {
	buf := make([]byte, 0, 1+len(k.Name))
	buf = append(buf, tagProfileRules)
	buf = encodeField(buf, k.Name)
	return buf
}

func decompressProfileRules(data []byte) (Key, error) {
	name, _, err := nextField(data, false)
	if err != nil {
		return nil, fmt.Errorf("ProfileRulesKey.Name: %w", err)
	}
	return ProfileRulesKey{ProfileKey: ProfileKey{Name: name}}, nil
}

// ProfileLabelsKey: [tag] [name]
func compressProfileLabels(k ProfileLabelsKey) []byte {
	buf := make([]byte, 0, 1+len(k.Name))
	buf = append(buf, tagProfileLabels)
	buf = encodeField(buf, k.Name)
	return buf
}

func decompressProfileLabels(data []byte) (Key, error) {
	name, _, err := nextField(data, false)
	if err != nil {
		return nil, fmt.Errorf("ProfileLabelsKey.Name: %w", err)
	}
	return ProfileLabelsKey{ProfileKey: ProfileKey{Name: name}}, nil
}

// HostEndpointKey: [tag] [hostname] 0xFE [endpointID]
func compressHostEndpoint(k HostEndpointKey) []byte {
	buf := make([]byte, 0, 1+len(k.Hostname)+len(k.EndpointID)+1)
	buf = append(buf, tagHostEndpoint)
	buf = encodeField(buf, k.Hostname)
	buf = append(buf, fieldDelimiter)
	buf = encodeField(buf, k.EndpointID)
	return buf
}

func decompressHostEndpoint(data []byte) (Key, error) {
	hostname, data, err := nextField(data, false)
	if err != nil {
		return nil, fmt.Errorf("HostEndpointKey.Hostname: %w", err)
	}
	endpoint, _, err := nextField(data, true)
	if err != nil {
		return nil, fmt.Errorf("HostEndpointKey.EndpointID: %w", err)
	}
	return HostEndpointKey{Hostname: hostname, EndpointID: endpoint}, nil
}

// ResourceKey global: [tag] [kind] 0xFE [name]
func compressResource(k ResourceKey) []byte {
	if k.Namespace == "" {
		buf := make([]byte, 0, 1+len(k.Kind)+len(k.Name)+1)
		buf = append(buf, tagResourceKeyGlobal)
		buf = encodeField(buf, k.Kind)
		buf = append(buf, fieldDelimiter)
		buf = encodeField(buf, k.Name)
		return buf
	}
	// ResourceKey namespaced: [tag] [kind] 0xFE [namespace] 0xFE [name]
	buf := make([]byte, 0, 1+len(k.Kind)+len(k.Namespace)+len(k.Name)+2)
	buf = append(buf, tagResourceKeyNamespaced)
	buf = encodeField(buf, k.Kind)
	buf = append(buf, fieldDelimiter)
	buf = encodeField(buf, k.Namespace)
	buf = append(buf, fieldDelimiter)
	buf = encodeField(buf, k.Name)
	return buf
}

func decompressResourceGlobal(data []byte) (Key, error) {
	kind, data, err := nextField(data, false)
	if err != nil {
		return nil, fmt.Errorf("ResourceKey.Kind: %w", err)
	}
	name, _, err := nextField(data, true)
	if err != nil {
		return nil, fmt.Errorf("ResourceKey.Name: %w", err)
	}
	return ResourceKey{Kind: kind, Name: name}, nil
}

func decompressResourceNamespaced(data []byte) (Key, error) {
	kind, data, err := nextField(data, false)
	if err != nil {
		return nil, fmt.Errorf("ResourceKey.Kind: %w", err)
	}
	ns, data, err := nextField(data, true)
	if err != nil {
		return nil, fmt.Errorf("ResourceKey.Namespace: %w", err)
	}
	name, _, err := nextField(data, true)
	if err != nil {
		return nil, fmt.Errorf("ResourceKey.Name: %w", err)
	}
	return ResourceKey{Kind: kind, Namespace: ns, Name: name}, nil
}

// NetworkSetKey: [tag] [name]
func compressNetworkSet(k NetworkSetKey) []byte {
	buf := make([]byte, 0, 1+len(k.Name))
	buf = append(buf, tagNetworkSet)
	buf = encodeField(buf, k.Name)
	return buf
}

func decompressNetworkSet(data []byte) (Key, error) {
	name, _, err := nextField(data, false)
	if err != nil {
		return nil, fmt.Errorf("NetworkSetKey.Name: %w", err)
	}
	return NetworkSetKey{Name: name}, nil
}

// Fallback: [tag] [raw default path bytes]
// The raw path is stored directly — no per-character encoding — since
// it is only used for uncommon key types.
func compressFallback(key Key) ([]byte, error) {
	path, err := key.defaultPath()
	if err != nil {
		return nil, fmt.Errorf("compressing unknown key type: %w", err)
	}
	buf := make([]byte, 0, 1+len(path))
	buf = append(buf, tagUnknown)
	buf = append(buf, path...)
	return buf, nil
}

func decompressFallback(data []byte) (Key, error) {
	path := string(data)
	key := KeyFromDefaultPath(path)
	if key == nil {
		return nil, fmt.Errorf("failed to parse fallback key path: %q", path)
	}
	return key, nil
}
