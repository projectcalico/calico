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
// keys in deduplicating buffers.  The overall length is carried by
// the Go string header, so the encoding needs no explicit length
// fields.
//
// Layout:
//
//	[type_tag: 1 byte] [5-bit packed stream]
//
// The type tag identifies the key type.  The remaining bytes are a
// bit-packed stream of 5-bit codes.
//
// The 5-bit code space (0–31) is assigned as follows:
//
//	0-25:  a-z   (lowercase letters — the dominant character class)
//	26:    '-'   (ubiquitous in Kubernetes names)
//	27:    '.'   (hostnames, profile names like kns.default)
//	28:    '/'   (workload IDs like namespace/pod)
//	29:    '_'   (occasional in identifiers)
//	30:    ESCAPE — the following two 5-bit codes encode a raw byte:
//	       raw_byte = (hi << 3) | lo, where hi is 0-31 and lo is 0-7.
//	31:    SPECIAL PREFIX — the next 5-bit code selects:
//	         0:    field delimiter (separates fields in a multi-field key)
//	         1-N:  dictionary entry (whole-field substitution, e.g.
//	               1=kubernetes, 2=eth0, …).  Dictionary indices
//	               beyond 31 use two 5-bit codes: (idx/31, idx%31+1)
//	               but in practice all current entries fit in one code.
//
// Everything is 5-bit codes packed into bytes.  The final byte is
// zero-padded on the right.  Compact characters cost 5 bits each
// (37.5% smaller than raw ASCII); escaped characters cost 15 bits
// (escape + hi + lo); dictionary entries cost 10 bits; and field
// delimiters cost 10 bits.

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

// 5-bit code assignments.
const (
	codeEscape  byte = 30
	codeSpecial byte = 31
)

// Sub-codes for the SPECIAL prefix (code 31).
const (
	specialDelimiter byte = 0 // field delimiter
	specialEnd       byte = 1 // end of stream
	// Dictionary indices start at 2.
	specialDictBase byte = 2
)

// Dictionary indices for common whole-field values.
// These are the sub-code values that follow codeSpecial.
// They start at specialDictBase (2) to leave room for
// specialDelimiter (0) and specialEnd (1).
const (
	dictKubernetes                    = specialDictBase + iota // 2
	dictEth0                                                  // 3
	dictDefault                                               // 4
	dictK8s                                                   // 5
	dictOpenstack                                             // 6
	dictCNI                                                   // 7
	dictNetworkPolicy                                         // 8
	dictGlobalNetworkPolicy                                   // 9
	dictStagedNetworkPolicy                                   // 10
	dictStagedGlobalNetworkPolicy                             // 11
	dictStagedKubernetesNetworkPolicy                         // 12
	dictFelixConfiguration                                    // 13
	// dictEnd is a sentinel; all valid indices are < dictEnd.
	dictEnd // 14
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
	for i := byte(specialDictBase); i < dictEnd; i++ {
		if dictStrings[i] != "" {
			dictLookup[dictStrings[i]] = i
		}
	}
}

// --- Compact alphabet (5-bit) ---
//
// Maps the 30 most common characters in Kubernetes resource names
// to 5-bit codes 0-29.  Codes 30 and 31 are reserved for escape
// and special prefix respectively.
//
//	 0-25: a-z
//	   26: '-'
//	   27: '.'
//	   28: '/'
//	   29: '_'
const compactMax5 = 30 // codes 0-29 are compact characters

// charTo5Bit maps byte values to 5-bit codes.
// 0xFF means the character requires the escape mechanism.
var charTo5Bit [256]byte

// fiveBitToChar maps 5-bit codes 0-29 back to byte values.
var fiveBitToChar [compactMax5]byte

func init() {
	for i := range charTo5Bit {
		charTo5Bit[i] = 0xFF
	}
	code := byte(0)
	for c := byte('a'); c <= 'z'; c++ {
		charTo5Bit[c] = code
		fiveBitToChar[code] = c
		code++
	}
	for _, c := range []byte{'-', '.', '/', '_'} {
		charTo5Bit[c] = code
		fiveBitToChar[code] = c
		code++
	}
}

// --- 5-bit stream packer/unpacker ---

// bitPacker accumulates 5-bit codes and packs them into bytes.
type bitPacker struct {
	buf  []byte
	acc  uint32 // accumulator for bits not yet flushed
	bits uint   // number of valid bits in acc (0-7 between flushes)
}

// writeCodes appends one or more 5-bit codes to the stream.
func (p *bitPacker) writeCodes(codes ...byte) {
	for _, c := range codes {
		p.acc = (p.acc << 5) | uint32(c&0x1F)
		p.bits += 5
		for p.bits >= 8 {
			p.bits -= 8
			p.buf = append(p.buf, byte(p.acc>>p.bits))
		}
	}
}

// flush pads the remaining bits (if any) with zeros and appends
// the final byte.
func (p *bitPacker) flush() {
	if p.bits > 0 {
		p.buf = append(p.buf, byte(p.acc<<(8-p.bits)))
	}
}

// result returns the packed byte slice.
func (p *bitPacker) result() []byte { return p.buf }

// bitUnpacker reads 5-bit codes from a packed byte stream.
type bitUnpacker struct {
	data []byte
	pos  int    // byte position in data
	acc  uint32 // bit accumulator
	bits uint   // number of valid bits in acc
}

// readCode returns the next 5-bit code, or -1 if exhausted.
func (u *bitUnpacker) readCode() int {
	for u.bits < 5 {
		if u.pos >= len(u.data) {
			if u.bits == 0 {
				return -1
			}
			// Remaining bits are zero-padding from flush;
			// treat as exhausted.
			return -1
		}
		u.acc = (u.acc << 8) | uint32(u.data[u.pos])
		u.pos++
		u.bits += 8
	}
	u.bits -= 5
	return int((u.acc >> u.bits) & 0x1F)
}

// --- Field encoding/decoding ---

// encodeField appends the 5-bit-encoded form of the string s to the
// bitPacker p.  If s matches a dictionary entry, it emits
// [codeSpecial, dictIndex] (10 bits).  Otherwise each character is
// encoded as its 5-bit compact code, or as the escape sequence
// [codeEscape, hi, lo] (15 bits) for non-compact characters.
func encodeField(p *bitPacker, s string) {
	if idx, ok := dictLookup[s]; ok {
		p.writeCodes(codeSpecial, idx)
		return
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if code := charTo5Bit[c]; code != 0xFF {
			p.writeCodes(code)
		} else {
			// Escape: code 30, then the raw byte split into
			// high 5 bits and low 3 bits (two 5-bit codes).
			p.writeCodes(codeEscape, c>>3, c&0x07)
		}
	}
}

// encodeDelimiter writes the field-delimiter code pair into the
// 5-bit stream: [codeSpecial, specialDelimiter].
func encodeDelimiter(p *bitPacker) {
	p.writeCodes(codeSpecial, specialDelimiter)
}

// decodeFields reads the 5-bit packed byte stream in data, splitting
// on delimiter codes, and returns each field as a string.
func decodeFields(data []byte) ([]string, error) {
	var fields []string
	var cur []byte

	u := &bitUnpacker{data: data}

	for {
		code := u.readCode()
		if code < 0 {
			// End of stream (exhausted bits) — emit the
			// final field.  This path is taken for streams
			// that consist of only compact characters with
			// no trailing special-end marker (shouldn't
			// happen in practice but is safe).
			fields = append(fields, string(cur))
			break
		}

		switch {
		case code < int(compactMax5):
			cur = append(cur, fiveBitToChar[code])

		case byte(code) == codeEscape:
			hi := u.readCode()
			lo := u.readCode()
			if hi < 0 || lo < 0 {
				return nil, fmt.Errorf("truncated escape sequence")
			}
			cur = append(cur, byte(hi<<3)|byte(lo))

		case byte(code) == codeSpecial:
			sub := u.readCode()
			if sub < 0 {
				return nil, fmt.Errorf("truncated special code")
			}
			switch {
			case byte(sub) == specialDelimiter:
				// Field delimiter.
				fields = append(fields, string(cur))
				cur = nil
			case byte(sub) == specialEnd:
				// End of stream — emit the final field and stop.
				fields = append(fields, string(cur))
				return fields, nil
			case byte(sub) >= specialDictBase && byte(sub) < dictEnd:
				// Dictionary entry.
				cur = append(cur, dictStrings[byte(sub)]...)
			default:
				return nil, fmt.Errorf("invalid special sub-code: %d", sub)
			}

		default:
			return nil, fmt.Errorf("invalid 5-bit code: %d", code)
		}
	}

	return fields, nil
}

// --- Public API ---

// CompressKey compresses a Key into a compact byte slice suitable for
// use as a Go map key (via string(result)).  The encoding eliminates
// redundant path prefixes and bit-packs common characters at 5 bits
// each, producing significantly shorter representations than the
// default path strings.
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

// --- Helper: compress N fields ---

// compressFields packs multiple fields into a single byte slice
// with the given type tag.  An end-of-stream marker is written
// after the last field so the decoder can distinguish padding
// zeros from real code-0 characters.
func compressFields(tag byte, fields ...string) []byte {
	// Estimate: tag + ~5/8 bytes per char + some overhead.
	totalChars := 0
	for _, f := range fields {
		totalChars += len(f)
	}
	p := &bitPacker{buf: make([]byte, 0, 1+totalChars*5/8+len(fields)+4)}
	p.buf = append(p.buf, tag)
	for i, f := range fields {
		if i > 0 {
			encodeDelimiter(p)
		}
		encodeField(p, f)
	}
	// Write end-of-stream marker so the decoder knows where
	// meaningful codes stop and padding begins.
	p.writeCodes(codeSpecial, specialEnd)
	p.flush()
	return p.result()
}

// --- Per-type compress/decompress ---

// WorkloadEndpointKey: [tag] [hostname] D [orchestratorID] D [workloadID] D [endpointID]
func compressWorkloadEndpoint(k WorkloadEndpointKey) []byte {
	return compressFields(tagWorkloadEndpoint,
		k.Hostname, k.OrchestratorID, k.WorkloadID, k.EndpointID)
}

func decompressWorkloadEndpoint(data []byte) (Key, error) {
	fields, err := decodeFields(data)
	if err != nil {
		return nil, fmt.Errorf("WorkloadEndpointKey: %w", err)
	}
	if len(fields) < 4 {
		return nil, fmt.Errorf("WorkloadEndpointKey: expected 4 fields, got %d", len(fields))
	}
	return WorkloadEndpointKey{
		Hostname:       fields[0],
		OrchestratorID: fields[1],
		WorkloadID:     fields[2],
		EndpointID:     fields[3],
	}, nil
}

// PolicyKey: [tag] [kind] D [namespace] D [name]
func compressPolicy(k PolicyKey) []byte {
	return compressFields(tagPolicy, k.Kind, k.Namespace, k.Name)
}

func decompressPolicy(data []byte) (Key, error) {
	fields, err := decodeFields(data)
	if err != nil {
		return nil, fmt.Errorf("PolicyKey: %w", err)
	}
	if len(fields) < 3 {
		return nil, fmt.Errorf("PolicyKey: expected 3 fields, got %d", len(fields))
	}
	return PolicyKey{Kind: fields[0], Namespace: fields[1], Name: fields[2]}, nil
}

// ProfileRulesKey: [tag] [name]
func compressProfileRules(k ProfileRulesKey) []byte {
	return compressFields(tagProfileRules, k.Name)
}

func decompressProfileRules(data []byte) (Key, error) {
	fields, err := decodeFields(data)
	if err != nil {
		return nil, fmt.Errorf("ProfileRulesKey: %w", err)
	}
	if len(fields) < 1 {
		return nil, fmt.Errorf("ProfileRulesKey: expected 1 field, got %d", len(fields))
	}
	return ProfileRulesKey{ProfileKey: ProfileKey{Name: fields[0]}}, nil
}

// ProfileLabelsKey: [tag] [name]
func compressProfileLabels(k ProfileLabelsKey) []byte {
	return compressFields(tagProfileLabels, k.Name)
}

func decompressProfileLabels(data []byte) (Key, error) {
	fields, err := decodeFields(data)
	if err != nil {
		return nil, fmt.Errorf("ProfileLabelsKey: %w", err)
	}
	if len(fields) < 1 {
		return nil, fmt.Errorf("ProfileLabelsKey: expected 1 field, got %d", len(fields))
	}
	return ProfileLabelsKey{ProfileKey: ProfileKey{Name: fields[0]}}, nil
}

// HostEndpointKey: [tag] [hostname] D [endpointID]
func compressHostEndpoint(k HostEndpointKey) []byte {
	return compressFields(tagHostEndpoint, k.Hostname, k.EndpointID)
}

func decompressHostEndpoint(data []byte) (Key, error) {
	fields, err := decodeFields(data)
	if err != nil {
		return nil, fmt.Errorf("HostEndpointKey: %w", err)
	}
	if len(fields) < 2 {
		return nil, fmt.Errorf("HostEndpointKey: expected 2 fields, got %d", len(fields))
	}
	return HostEndpointKey{Hostname: fields[0], EndpointID: fields[1]}, nil
}

// ResourceKey global: [tag] [kind] D [name]
// ResourceKey namespaced: [tag] [kind] D [namespace] D [name]
func compressResource(k ResourceKey) []byte {
	if k.Namespace == "" {
		return compressFields(tagResourceKeyGlobal, k.Kind, k.Name)
	}
	return compressFields(tagResourceKeyNamespaced, k.Kind, k.Namespace, k.Name)
}

func decompressResourceGlobal(data []byte) (Key, error) {
	fields, err := decodeFields(data)
	if err != nil {
		return nil, fmt.Errorf("ResourceKey: %w", err)
	}
	if len(fields) < 2 {
		return nil, fmt.Errorf("ResourceKey: expected 2 fields, got %d", len(fields))
	}
	return ResourceKey{Kind: fields[0], Name: fields[1]}, nil
}

func decompressResourceNamespaced(data []byte) (Key, error) {
	fields, err := decodeFields(data)
	if err != nil {
		return nil, fmt.Errorf("ResourceKey: %w", err)
	}
	if len(fields) < 3 {
		return nil, fmt.Errorf("ResourceKey: expected 3 fields, got %d", len(fields))
	}
	return ResourceKey{Kind: fields[0], Namespace: fields[1], Name: fields[2]}, nil
}

// NetworkSetKey: [tag] [name]
func compressNetworkSet(k NetworkSetKey) []byte {
	return compressFields(tagNetworkSet, k.Name)
}

func decompressNetworkSet(data []byte) (Key, error) {
	fields, err := decodeFields(data)
	if err != nil {
		return nil, fmt.Errorf("NetworkSetKey: %w", err)
	}
	if len(fields) < 1 {
		return nil, fmt.Errorf("NetworkSetKey: expected 1 field, got %d", len(fields))
	}
	return NetworkSetKey{Name: fields[0]}, nil
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
