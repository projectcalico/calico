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
	"strings"
)

// Compressed key format
// =====================
//
// Compressed keys are designed to be used directly as Go
// map[CompressedKey]… keys in deduplicating buffers.  The overall
// length is carried by the Go string header, so the encoding needs
// no explicit length fields.
//
// The public API operates on default-path strings (the same strings
// used as etcd/KDD keys) and returns CompressedKey values:
//
//   CompressKeyPath(path string) CompressedKey
//   DecompressKeyPath(compressed CompressedKey) (string, error)
//
// The path is pattern-matched to select the best per-type
// compression; unrecognised paths are stored with a fallback tag.
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
//	         1:    end-of-stream marker
//	         2-13: dictionary entry (whole-field substitution, e.g.
//	               2=kubernetes, 3=eth0, …); dictEnd (14) is the
//	               current upper bound, leaving room for growth
//	               within one 5-bit sub-code (max 31).
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
	tagWorkloadEndpointK8s // k8s orchestrator + eth0 endpoint; stores only [hostname] D [workloadID]
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
	dictKubernetes                      = specialDictBase + iota // 2
	dictEth0                                                     // 3
	dictDefault                                                  // 4
	dictK8s                                                      // 5
	dictOpenstack                                                // 6
	dictCNI                                                      // 7
	dictNetworkPolicies                                          // 8
	dictGlobalNetworkPolicies                                    // 9
	dictStagedNetworkPolicies                                    // 10
	dictStagedGlobalNetworkPolicies                              // 11
	dictStagedKubernetesNetworkPolicies                          // 12
	dictFelixConfigurations                                      // 13
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
	dictStrings[dictNetworkPolicies] = "networkpolicies"
	dictStrings[dictGlobalNetworkPolicies] = "globalnetworkpolicies"
	dictStrings[dictStagedNetworkPolicies] = "stagednetworkpolicies"
	dictStrings[dictStagedGlobalNetworkPolicies] = "stagedglobalnetworkpolicies"
	dictStrings[dictStagedKubernetesNetworkPolicies] = "stagedkubernetesnetworkpolicies"
	dictStrings[dictFelixConfigurations] = "felixconfigurations"

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
//	0-25: a-z
//	  26: '-'
//	  27: '.'
//	  28: '/'
//	  29: '_'
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

// CompressedKey is a compact representation of a default-path string.
// It is suitable for direct use as a Go map key.
type CompressedKey string

// Expand decompresses the CompressedKey back into its original
// default-path string.  It is a convenience wrapper around
// DecompressKeyPath.
func (k CompressedKey) Expand() (string, error) {
	return DecompressKeyPath(k)
}

// CompressKeyPath compresses a default-path string into a compact
// CompressedKey suitable for direct use as a Go map[CompressedKey]…
// key.  The path is pattern-matched to select the best per-type
// compression; unrecognised paths are stored with a fallback tag.
func CompressKeyPath(path string) CompressedKey {
	return CompressedKey(compressKeyPathToBytes(path))
}

func compressKeyPathToBytes(path string) []byte {
	// Only match known patterns for canonical paths starting with "/".
	if len(path) == 0 || path[0] != '/' {
		// Fallback: store the raw path.
		buf := make([]byte, 0, 1+len(path))
		buf = append(buf, tagUnknown)
		buf = append(buf, path...)
		return buf
	}

	// Strip leading "/" for splitting.
	parts := strings.Split(path[1:], "/")

	if len(parts) >= 3 && parts[0] == "calico" {
		switch parts[1] {
		case "v1":
			switch parts[2] {
			case "host":
				if len(parts) >= 5 {
					switch parts[4] {
					case "workload":
						// /calico/v1/host/<hostname>/workload/<orch>/<workload>/endpoint/<ep>
						if len(parts) == 9 && parts[7] == "endpoint" {
							if parts[5] == "kubernetes" && parts[8] == "eth0" {
								// Optimised: k8s+eth0 stores only hostname and workloadID.
								return compressFields(tagWorkloadEndpointK8s,
									parts[3], parts[6])
							}
							return compressFields(tagWorkloadEndpoint,
								parts[3], parts[5], parts[6], parts[8])
						}
					case "endpoint":
						// /calico/v1/host/<hostname>/endpoint/<endpointID>
						if len(parts) == 6 {
							return compressFields(tagHostEndpoint,
								parts[3], parts[5])
						}
					}
				}
			case "netset":
				// /calico/v1/netset/<name>
				if len(parts) == 4 {
					return compressFields(tagNetworkSet, parts[3])
				}
			case "policy":
				if len(parts) >= 6 {
					switch parts[3] {
					case "profile":
						// /calico/v1/policy/profile/<name>/rules
						// /calico/v1/policy/profile/<name>/labels
						if len(parts) == 6 {
							switch parts[5] {
							case "rules":
								return compressFields(tagProfileRules, parts[4])
							case "labels":
								return compressFields(tagProfileLabels, parts[4])
							}
						}
					default:
						// /calico/v1/policy/<kind>/<namespace>/<name>
						if len(parts) == 6 {
							return compressFields(tagPolicy,
								parts[3], parts[4], parts[5])
						}
					}
				}
			}
		case "resources":
			// /calico/resources/v3/projectcalico.org/<plural>/<name>           (global)
			// /calico/resources/v3/projectcalico.org/<plural>/<namespace>/<name> (namespaced)
			if len(parts) >= 6 && parts[2] == "v3" && parts[3] == "projectcalico.org" {
				switch len(parts) {
				case 6:
					return compressFields(tagResourceKeyGlobal,
						parts[4], parts[5])
				case 7:
					return compressFields(tagResourceKeyNamespaced,
						parts[4], parts[5], parts[6])
				}
			}
		}
	}

	// Fallback: store the raw path.
	buf := make([]byte, 0, 1+len(path))
	buf = append(buf, tagUnknown)
	buf = append(buf, path...)
	return buf
}

// DecompressKeyPath decompresses a CompressedKey produced by
// CompressKeyPath back into the original default-path string.
func DecompressKeyPath(compressed CompressedKey) (string, error) {
	data := []byte(compressed)
	if len(data) == 0 {
		return "", fmt.Errorf("empty compressed key")
	}
	switch data[0] {
	case tagWorkloadEndpoint:
		return decompressWorkloadEndpointPath(data[1:])
	case tagWorkloadEndpointK8s:
		return decompressWorkloadEndpointK8sPath(data[1:])
	case tagPolicy:
		return decompressPolicyPath(data[1:])
	case tagProfileRules:
		return decompressProfilePath(data[1:], "rules")
	case tagProfileLabels:
		return decompressProfilePath(data[1:], "labels")
	case tagHostEndpoint:
		return decompressHostEndpointPath(data[1:])
	case tagResourceKeyGlobal:
		return decompressResourcePath(data[1:], false)
	case tagResourceKeyNamespaced:
		return decompressResourcePath(data[1:], true)
	case tagNetworkSet:
		return decompressNetworkSetPath(data[1:])
	case tagUnknown:
		return string(data[1:]), nil
	default:
		return "", fmt.Errorf("unknown key type tag: 0x%02x", data[0])
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

// --- Per-type path decompression ---

// decompressWorkloadEndpointPath: fields = [hostname, orch, workload, endpoint]
// → /calico/v1/host/<hostname>/workload/<orch>/<workload>/endpoint/<ep>
func decompressWorkloadEndpointPath(data []byte) (string, error) {
	fields, err := decodeFields(data)
	if err != nil {
		return "", fmt.Errorf("WorkloadEndpointPath: %w", err)
	}
	if len(fields) < 4 {
		return "", fmt.Errorf("WorkloadEndpointPath: expected 4 fields, got %d", len(fields))
	}
	return fmt.Sprintf("/calico/v1/host/%s/workload/%s/%s/endpoint/%s",
		fields[0], fields[1], fields[2], fields[3]), nil
}

// decompressWorkloadEndpointK8sPath: fields = [hostname, workload]
// → /calico/v1/host/<hostname>/workload/kubernetes/<workload>/endpoint/eth0
func decompressWorkloadEndpointK8sPath(data []byte) (string, error) {
	fields, err := decodeFields(data)
	if err != nil {
		return "", fmt.Errorf("WorkloadEndpointK8sPath: %w", err)
	}
	if len(fields) < 2 {
		return "", fmt.Errorf("WorkloadEndpointK8sPath: expected 2 fields, got %d", len(fields))
	}
	return fmt.Sprintf("/calico/v1/host/%s/workload/kubernetes/%s/endpoint/eth0",
		fields[0], fields[1]), nil
}

// decompressPolicyPath: fields = [kind, namespace, name]
// → /calico/v1/policy/<kind>/<namespace>/<name>
func decompressPolicyPath(data []byte) (string, error) {
	fields, err := decodeFields(data)
	if err != nil {
		return "", fmt.Errorf("PolicyPath: %w", err)
	}
	if len(fields) < 3 {
		return "", fmt.Errorf("PolicyPath: expected 3 fields, got %d", len(fields))
	}
	return fmt.Sprintf("/calico/v1/policy/%s/%s/%s",
		fields[0], fields[1], fields[2]), nil
}

// decompressProfilePath: fields = [name]
// → /calico/v1/policy/profile/<name>/<suffix>
func decompressProfilePath(data []byte, suffix string) (string, error) {
	fields, err := decodeFields(data)
	if err != nil {
		return "", fmt.Errorf("ProfilePath: %w", err)
	}
	if len(fields) < 1 {
		return "", fmt.Errorf("ProfilePath: expected 1 field, got %d", len(fields))
	}
	return fmt.Sprintf("/calico/v1/policy/profile/%s/%s",
		fields[0], suffix), nil
}

// decompressHostEndpointPath: fields = [hostname, endpointID]
// → /calico/v1/host/<hostname>/endpoint/<endpointID>
func decompressHostEndpointPath(data []byte) (string, error) {
	fields, err := decodeFields(data)
	if err != nil {
		return "", fmt.Errorf("HostEndpointPath: %w", err)
	}
	if len(fields) < 2 {
		return "", fmt.Errorf("HostEndpointPath: expected 2 fields, got %d", len(fields))
	}
	return fmt.Sprintf("/calico/v1/host/%s/endpoint/%s",
		fields[0], fields[1]), nil
}

// decompressResourcePath: fields = [plural, name] or [plural, namespace, name]
// → /calico/resources/v3/projectcalico.org/<plural>/<name>
// → /calico/resources/v3/projectcalico.org/<plural>/<namespace>/<name>
func decompressResourcePath(data []byte, namespaced bool) (string, error) {
	fields, err := decodeFields(data)
	if err != nil {
		return "", fmt.Errorf("ResourcePath: %w", err)
	}
	if namespaced {
		if len(fields) < 3 {
			return "", fmt.Errorf("ResourcePath: expected 3 fields, got %d", len(fields))
		}
		return fmt.Sprintf("/calico/resources/v3/projectcalico.org/%s/%s/%s",
			fields[0], fields[1], fields[2]), nil
	}
	if len(fields) < 2 {
		return "", fmt.Errorf("ResourcePath: expected 2 fields, got %d", len(fields))
	}
	return fmt.Sprintf("/calico/resources/v3/projectcalico.org/%s/%s",
		fields[0], fields[1]), nil
}

// decompressNetworkSetPath: fields = [name]
// → /calico/v1/netset/<name>
func decompressNetworkSetPath(data []byte) (string, error) {
	fields, err := decodeFields(data)
	if err != nil {
		return "", fmt.Errorf("NetworkSetPath: %w", err)
	}
	if len(fields) < 1 {
		return "", fmt.Errorf("NetworkSetPath: expected 1 field, got %d", len(fields))
	}
	return fmt.Sprintf("/calico/v1/netset/%s", fields[0]), nil
}
