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
//	[type_tag: 1 byte] [6-bit packed stream]
//
// The type tag identifies the key type.  The remaining bytes are a
// bit-packed stream of 6-bit codes.
//
// The 6-bit code space (0–63) is assigned as follows:
//
//	 0-25: a-z   (lowercase letters — the dominant character class)
//	26-35: 0-9   (digits — very common in k8s names, IPs, pod hashes)
//	   36: '-'   (ubiquitous in Kubernetes names)
//	   37: '.'   (hostnames, profile names like kns.default)
//	   38: '/'   (workload IDs like namespace/pod)
//	   39: '_'   (occasional in identifiers)
//	   40: '%'   (URL-encoded chars in workload IDs, e.g. %2f)
//	   41: field delimiter (separates fields in a multi-field key)
//	   42: end-of-stream marker
//	43-54: dictionary entries (whole-field substitution, e.g.
//	       43=kubernetes, 44=eth0, …); allocated at init time.
//	55-61: (reserved for future dictionary entries)
//	   62: ESCAPE — the following two 6-bit codes encode a raw byte:
//	       raw_byte = (hi << 4) | lo, where hi is 0-15 and lo is 0-15.
//	   63: (reserved)
//
// Everything is 6-bit codes packed into bytes.  The final byte is
// zero-padded on the right.  Compact characters cost 6 bits each
// (25% smaller than raw ASCII); escaped characters cost 18 bits
// (escape + hi + lo); dictionary entries, field delimiters, and
// end-of-stream markers each cost just 6 bits.

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

// 6-bit code assignments.
const (
	codeDelimiter byte = 41 // field delimiter
	codeEnd       byte = 42 // end of stream
	codeDictBase  byte = 43 // first dictionary entry code
	codeDictMax   byte = 55 // exclusive upper bound (codes 43-54 = 12 entries)
	codeEscape    byte = 62 // next two codes encode a raw byte
)

// dictStrings maps dictionary codes (offset from codeDictBase) to
// their string values.  Populated by registerDictEntry during init.
var dictStrings []string

// dictLookup maps string values to their 6-bit dictionary codes.
var dictLookup map[string]byte

// nextDictCode is the next available dictionary code.  All valid
// dictionary codes satisfy codeDictBase <= code < nextDictCode.
var nextDictCode byte

// registerDictEntry adds a word to the dictionary, assigning it the
// next available 6-bit code.  Must only be called during init().
func registerDictEntry(word string) byte {
	if nextDictCode >= codeDictMax {
		panic("dictionary full: no more 6-bit codes available")
	}
	code := nextDictCode
	nextDictCode++
	dictStrings = append(dictStrings, word)
	dictLookup[word] = code
	return code
}

func init() {
	nextDictCode = codeDictBase
	dictStrings = make([]string, 0, int(codeDictMax-codeDictBase))
	dictLookup = make(map[string]byte, int(codeDictMax-codeDictBase))

	registerDictEntry("kubernetes")
	registerDictEntry("eth0")
	registerDictEntry("default")
	registerDictEntry("k8s")
	registerDictEntry("openstack")
	registerDictEntry("cni")
	registerDictEntry("networkpolicies")
	registerDictEntry("globalnetworkpolicies")
	registerDictEntry("stagednetworkpolicies")
	registerDictEntry("stagedglobalnetworkpolicies")
	registerDictEntry("stagedkubernetesnetworkpolicies")
	registerDictEntry("felixconfigurations")
}

// --- Compact alphabet (6-bit) ---
//
// Maps the most common characters in Kubernetes resource names
// to 6-bit codes 0-61.  Codes 62 and 63 are reserved for escape
// and special prefix respectively.
//
//	 0-25: a-z
//	26-35: 0-9
//	   36: '-'
//	   37: '.'
//	   38: '/'
//	   39: '_'
//	   40: '%'
const compactMax6 = 41 // codes 0-40 are compact characters

// charTo6Bit maps byte values to 6-bit codes.
// 0xFF means the character requires the escape mechanism.
var charTo6Bit [256]byte

// sixBitToChar maps 6-bit codes 0-40 back to byte values.
var sixBitToChar [compactMax6]byte

func init() {
	for i := range charTo6Bit {
		charTo6Bit[i] = 0xFF
	}
	code := byte(0)
	for c := byte('a'); c <= 'z'; c++ {
		charTo6Bit[c] = code
		sixBitToChar[code] = c
		code++
	}
	for c := byte('0'); c <= '9'; c++ {
		charTo6Bit[c] = code
		sixBitToChar[code] = c
		code++
	}
	for _, c := range []byte{'-', '.', '/', '_', '%'} {
		charTo6Bit[c] = code
		sixBitToChar[code] = c
		code++
	}
}

// --- 6-bit stream packer/unpacker ---

// bitPacker accumulates 6-bit codes and packs them into bytes.
type bitPacker struct {
	buf  []byte
	acc  uint32 // accumulator for bits not yet flushed
	bits uint   // number of valid bits in acc (0-7 between flushes)
}

// writeCodes appends one or more 6-bit codes to the stream.
func (p *bitPacker) writeCodes(codes ...byte) {
	for _, c := range codes {
		p.acc = (p.acc << 6) | uint32(c&0x3F)
		p.bits += 6
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

// bitUnpacker reads 6-bit codes from a packed byte stream.
type bitUnpacker struct {
	data []byte
	pos  int    // byte position in data
	acc  uint32 // bit accumulator
	bits uint   // number of valid bits in acc
}

// readCode returns the next 6-bit code, or -1 if exhausted.
func (u *bitUnpacker) readCode() int {
	for u.bits < 6 {
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
	u.bits -= 6
	return int((u.acc >> u.bits) & 0x3F)
}

// --- Field encoding/decoding ---

// encodeField appends the 6-bit-encoded form of the string s to the
// bitPacker p.  If s matches a dictionary entry, it emits a single
// dictionary code (6 bits).  Otherwise each character is encoded as
// its 6-bit compact code, or as the escape sequence
// [codeEscape, hi, lo] (18 bits) for non-compact characters.
func encodeField(p *bitPacker, s string) {
	if code, ok := dictLookup[s]; ok {
		p.writeCodes(code)
		return
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if code := charTo6Bit[c]; code != 0xFF {
			p.writeCodes(code)
		} else {
			// Escape: code 62, then the raw byte split into
			// high 4 bits and low 4 bits (two 6-bit codes).
			p.writeCodes(codeEscape, c>>4, c&0x0F)
		}
	}
}

// encodeDelimiter writes the field-delimiter code into the 6-bit
// stream: a single codeDelimiter (6 bits).
func encodeDelimiter(p *bitPacker) {
	p.writeCodes(codeDelimiter)
}

// decodeFields reads the 6-bit packed byte stream in data, splitting
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
			// no trailing end marker (shouldn't happen in
			// practice but is safe).
			fields = append(fields, string(cur))
			break
		}

		bc := byte(code)
		switch {
		case bc < compactMax6:
			cur = append(cur, sixBitToChar[bc])

		case bc == codeDelimiter:
			// Field delimiter.
			fields = append(fields, string(cur))
			cur = nil

		case bc == codeEnd:
			// End of stream — emit the final field and stop.
			fields = append(fields, string(cur))
			return fields, nil

		case bc >= codeDictBase && bc < nextDictCode:
			// Dictionary entry.
			cur = append(cur, dictStrings[bc-codeDictBase]...)

		case bc == codeEscape:
			hi := u.readCode()
			lo := u.readCode()
			if hi < 0 || lo < 0 {
				return nil, fmt.Errorf("truncated escape sequence")
			}
			cur = append(cur, byte(hi<<4)|byte(lo))

		default:
			return nil, fmt.Errorf("invalid 6-bit code: %d", code)
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
	// Estimate: tag + ~6/8 bytes per char + some overhead.
	totalChars := 0
	for _, f := range fields {
		totalChars += len(f)
	}
	p := &bitPacker{buf: make([]byte, 0, 1+totalChars*6/8+len(fields)+4)}
	p.buf = append(p.buf, tag)
	for i, f := range fields {
		if i > 0 {
			encodeDelimiter(p)
		}
		encodeField(p, f)
	}
	// Write end-of-stream marker so the decoder knows where
	// meaningful codes stop and padding begins.
	p.writeCodes(codeEnd)
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
