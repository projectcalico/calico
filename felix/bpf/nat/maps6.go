// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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

package nat

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/ip"
)

//	struct calico_nat_v4_key {
//	   uint32_t prefixLen;
//	   uint32_t addr; // NBO
//	   uint16_t port; // HBO
//	   uint8_t protocol;
//	   uint32_t saddr;
//	   uint8_t pad;
//	};
const frontendKeyV6Size = 40

//	struct calico_nat {
//		uint32_t addr;
//		uint16_t port;
//		uint8_t  protocol;
//		uint8_t  pad;
//	};
const frontendAffKeyV6Size = 20

//	struct calico_nat_v4_value {
//	   uint32_t id;
//	   uint32_t count;
//	   uint32_t local;
//	   uint32_t affinity_timeo;
//	   uint32_t flags;
//	};
const frontendValueV6Size = 20

//	struct calico_nat_secondary_v4_key {
//	  uint32_t id;
//	  uint32_t ordinal;
//	};
const backendKeyV6Size = 8

//	struct calico_nat_dest {
//	   uint32_t addr;
//	   uint16_t port;
//	   uint8_t pad[2];
//	};
const backendValueV6Size = 20

// (sizeof(addr) + sizeof(port) + sizeof(proto)) in bits
const ZeroCIDRV6PrefixLen = (16 + 2 + 1) * 8

var ZeroCIDRV6 = ip.MustParseCIDROrIP("::/0").(ip.V6CIDR)

type FrontendKeyV6 [frontendKeyV6Size]byte

func NewNATKeyV6(addr net.IP, port uint16, protocol uint8) FrontendKeyV6 {
	return NewNATKeyV6Src(addr, port, protocol, ZeroCIDRV6)
}

func NewNATKeyV6Src(addr net.IP, port uint16, protocol uint8, cidr ip.V6CIDR) FrontendKeyV6 {
	var k FrontendKeyV6
	prefixlen := ZeroCIDRV6PrefixLen
	addr = addr.To16()
	binary.LittleEndian.PutUint32(k[:4], uint32(prefixlen)+uint32(cidr.Prefix()))
	copy(k[4:20], addr)
	binary.LittleEndian.PutUint16(k[20:22], port)
	k[22] = protocol
	copy(k[23:39], cidr.Addr().AsNetIP().To16())
	return k
}

func (k FrontendKeyV6) Proto() uint8 {
	return k[22]
}

func (k FrontendKeyV6) Addr() net.IP {
	return k[4:20]
}

func (k FrontendKeyV6) srcAddr() ip.Addr {
	var addr ip.V6Addr
	copy(addr[:], k[23:39])
	return addr
}

// This function returns the Prefix length of the source CIDR
func (k FrontendKeyV6) SrcPrefixLen() uint32 {
	return k.PrefixLen() - ZeroCIDRV6PrefixLen
}

func (k FrontendKeyV6) SrcCIDR() ip.CIDR {
	return ip.CIDRFromAddrAndPrefix(k.srcAddr(), int(k.SrcPrefixLen()))
}

func (k FrontendKeyV6) PrefixLen() uint32 {
	return binary.LittleEndian.Uint32(k[0:4])
}

func (k FrontendKeyV6) Port() uint16 {
	return binary.LittleEndian.Uint16(k[20:22])
}

func (k FrontendKeyV6) AsBytes() []byte {
	return k[:]
}

func (k FrontendKeyV6) Affinitykey() []byte {
	return k[4:12]
}

func (k FrontendKeyV6) String() string {
	return fmt.Sprintf("NATKeyV6{Proto:%v Addr:%v Port:%v SrcAddr:%v}", k.Proto(), k.Addr(), k.Port(), k.SrcCIDR())
}

func FrontendKeyV6FromBytes(b []byte) FrontendKeyV6 {
	var k FrontendKeyV6
	copy(k[:], b)
	return k
}

type FrontendValueV6 = FrontendValue

func NewNATValueV6(id uint32, count, local, affinityTimeo uint32) FrontendValueV6 {
	return NewNATValue(id, count, local, affinityTimeo)
}

func NewNATValueV6WithFlags(id uint32, count, local, affinityTimeo, flags uint32) FrontendValueV6 {
	v := NewNATValue(id, count, local, affinityTimeo)
	binary.LittleEndian.PutUint32(v[16:20], flags)
	return v
}

func FrontendValueV6FromBytes(b []byte) FrontendValueV6 {
	var v FrontendValueV6
	copy(v[:], b)
	return v
}

type BackendKeyV6 = BackendKey

func NewNATBackendKeyV6(id, ordinal uint32) BackendKeyV6 {
	return NewNATBackendKey(id, ordinal)
}

func BackendKeyV6FromBytes(b []byte) BackendKeyV6 {
	var k BackendKeyV6
	copy(k[:], b)
	return k
}

type BackendValueV6 [backendValueV6Size]byte

func NewNATBackendValueV6(addr net.IP, port uint16) BackendValueV6 {
	var k BackendValueV6
	addr = addr.To16()
	copy(k[:16], addr)
	binary.LittleEndian.PutUint16(k[16:18], port)
	return k
}

func (k BackendValueV6) Addr() net.IP {
	return k[:16]
}

func (k BackendValueV6) Port() uint16 {
	return binary.LittleEndian.Uint16(k[4:6])
}

func (k BackendValueV6) String() string {
	return fmt.Sprintf("NATBackendValueV6{Addr:%v Port:%v}", k.Addr(), k.Port())
}

func (k BackendValueV6) AsBytes() []byte {
	return k[:]
}

func BackendValueV6FromBytes(b []byte) BackendValueV6 {
	var v BackendValueV6
	copy(v[:], b)
	return v
}

var FrontendMapV6Parameters = maps.MapParameters{
	Type:       "lpm_trie",
	KeySize:    frontendKeyV6Size,
	ValueSize:  frontendValueV6Size,
	MaxEntries: 64 * 1024,
	Name:       "cali_v6_nat_fe",
	Flags:      unix.BPF_F_NO_PREALLOC,
	Version:    3,
}

func FrontendMapV6() maps.MapWithExistsCheck {
	return maps.NewPinnedMap(FrontendMapV6Parameters)
}

var BackendMapV6Parameters = maps.MapParameters{
	Type:       "hash",
	KeySize:    backendKeyV6Size,
	ValueSize:  backendValueV6Size,
	MaxEntries: 256 * 1024,
	Name:       "cali_v6_nat_be",
	Flags:      unix.BPF_F_NO_PREALLOC,
}

func BackendMapV6() maps.MapWithExistsCheck {
	return maps.NewPinnedMap(BackendMapV6Parameters)
}

// NATMapMem represents FrontendMap loaded into memory
type MapMemV6 map[FrontendKeyV6]FrontendValueV6

// Equal compares keys and values of the NATMapMem
func (m MapMemV6) Equal(cmp MapMemV6) bool {
	if len(m) != len(cmp) {
		return false
	}

	for k, v := range m {
		v2, ok := cmp[k]
		if !ok || v != v2 {
			return false
		}
	}

	return true
}

// LoadFrontendMap loads the NAT map into a go map or returns an error
func LoadFrontendMapV6(m maps.Map) (MapMemV6, error) {
	ret := make(MapMemV6)

	if err := m.Open(); err != nil {
		return nil, err
	}

	iterFn := MapMemV6Iter(ret)

	err := m.Iter(func(k, v []byte) maps.IteratorAction {
		iterFn(k, v)
		return maps.IterNone
	})
	if err != nil {
		ret = nil
	}

	return ret, err
}

// MapMemIter returns maps.MapIter that loads the provided NATMapMem
func MapMemV6Iter(m MapMemV6) func(k, v []byte) {
	ks := len(FrontendKeyV6{})
	vs := len(FrontendValueV6{})

	return func(k, v []byte) {
		var key FrontendKeyV6
		copy(key[:ks], k[:ks])

		var val FrontendValueV6
		copy(val[:vs], v[:vs])

		m[key] = val
	}
}

// BackendMapMemV6 represents a NATBackend loaded into memory
type BackendMapMemV6 map[BackendKeyV6]BackendValueV6

// Equal compares keys and values of the NATBackendMapMem
func (m BackendMapMemV6) Equal(cmp BackendMapMemV6) bool {
	if len(m) != len(cmp) {
		return false
	}

	for k, v := range m {
		v2, ok := cmp[k]
		if !ok || v != v2 {
			return false
		}
	}

	return true
}

// LoadBackendMap loads the NATBackend map into a go map or returns an error
func LoadBackendMapV6(m maps.Map) (BackendMapMemV6, error) {
	ret := make(BackendMapMemV6)

	if err := m.Open(); err != nil {
		return nil, err
	}

	iterFn := BackendMapMemV6Iter(ret)

	err := m.Iter(func(k, v []byte) maps.IteratorAction {
		iterFn(k, v)
		return maps.IterNone
	})
	if err != nil {
		ret = nil
	}

	return ret, err
}

// BackendMapMemIter returns maps.MapIter that loads the provided NATBackendMapMem
func BackendMapMemV6Iter(m BackendMapMemV6) func(k, v []byte) {
	ks := len(BackendKeyV6{})
	vs := len(BackendValueV6{})

	return func(k, v []byte) {
		var key BackendKeyV6
		copy(key[:ks], k[:ks])

		var val BackendValueV6
		copy(val[:vs], v[:vs])

		m[key] = val
	}
}

// struct calico_nat_v4_affinity_key {
//    struct calico_nat_v4 nat_key;
// 	  uint32_t client_ip;
// 	  uint32_t padding;
// };

const affinityKeyV6Size = frontendAffKeyV6Size + 16 + 4

// AffinityKeyV6 is a key into the affinity table that consist of FrontendKeyV6 and
// the client's IP
type AffinityKeyV6 [affinityKeyV6Size]byte

type FrontEndAffinityKeyV6 [frontendAffKeyV6Size]byte

func (k FrontEndAffinityKeyV6) AsBytes() []byte {
	return k[:]
}

func (k FrontEndAffinityKeyV6) String() string {
	return fmt.Sprintf("FrontEndAffinityKeyV6{Proto:%v Addr:%v Port:%v}", k.Proto(), k.Addr(), k.Port())
}

func (k FrontEndAffinityKeyV6) Proto() uint8 {
	return k[6]
}

func (k FrontEndAffinityKeyV6) Addr() net.IP {
	return k[0:16]
}

func (k FrontEndAffinityKeyV6) Port() uint16 {
	return binary.LittleEndian.Uint16(k[16:18])
}

// NewAffinityKey create a new AffinityKeyV6 from a clientIP and FrontendKeyV6
func NewAffinityKeyV6(clientIP net.IP, fEndKey FrontendKeyV6) AffinityKeyV6 {
	var k AffinityKeyV6

	copy(k[:], fEndKey[4:4+frontendAffKeyV6Size])

	addr := clientIP.To16()
	copy(k[frontendAffKeyV6Size:frontendAffKeyV6Size+16], addr)
	return k
}

// ClientIP returns the ClientIP part of the key
func (k AffinityKeyV6) ClientIP() net.IP {
	return k[frontendAffKeySize : frontendAffKeySize+4]
}

// FrontendKeyV6 returns the FrontendKeyV6 part of the key
func (k AffinityKeyV6) FrontendAffinityKey() FrontEndAffinityKeyV6 {
	var f FrontEndAffinityKeyV6
	copy(f[:], k[:frontendAffKeySize])

	return f
}

func (k AffinityKeyV6) String() string {
	return fmt.Sprintf("AffinityKeyV6{ClientIP:%v %s}", k.ClientIP(), k.FrontendAffinityKey())
}

// AsBytes returns the key as []byte
func (k AffinityKeyV6) AsBytes() []byte {
	return k[:]
}

// struct calico_nat_v4_affinity_val {
//    struct calico_nat_dest;
//    uint64_t ts;
// };

const affinityValueV6Size = backendValueV6Size + 4 + 8

// AffinityValueV6 represents a backend picked by the affinity and the timestamp
// of its creating
type AffinityValueV6 [affinityValueV6Size]byte

// NewAffinityValue creates a value from a timestamp and a backend
func NewAffinityValueV6(ts uint64, backend BackendValueV6) AffinityValueV6 {
	var v AffinityValueV6

	copy(v[:], backend[:])
	binary.LittleEndian.PutUint64(v[backendValueV6Size:backendValueV6Size+8], ts)

	return v
}

// Timestamp returns the timestamp of the entry. It is generated by
// bpf_ktime_get_ns which returns the time since the system boot in nanoseconds
// - it is the monotonic clock reading, which is compatible with time operations
// in time package.
func (v AffinityValueV6) Timestamp() time.Duration {
	nano := binary.LittleEndian.Uint64(v[backendValueSize : backendValueSize+8])
	return time.Duration(nano) * time.Nanosecond
}

// Backend returns the backend the affinity ties the frontend + client to.
func (v AffinityValueV6) Backend() BackendValueV6 {
	var b BackendValueV6

	copy(b[:], v[:backendValueSize])

	return b
}

func (v AffinityValueV6) String() string {
	return fmt.Sprintf("AffinityValueV6{Timestamp:%d,Backend:%v}", v.Timestamp(), v.Backend())
}

// AsBytes returns the value as []byte
func (v AffinityValueV6) AsBytes() []byte {
	return v[:]
}

// AffinityMapParameters describe the AffinityMap
var AffinityMapV6Parameters = maps.MapParameters{
	Type:       "lru_hash",
	KeySize:    affinityKeyV6Size,
	ValueSize:  affinityValueV6Size,
	MaxEntries: 64 * 1024,
	Name:       "cali_v6_nat_aff",
}

// AffinityMap returns an instance of an affinity map
func AffinityMapV6() maps.Map {
	return maps.NewPinnedMap(AffinityMapV6Parameters)
}

// AffinityMapMem represents affinity map in memory
type AffinityMapMemV6 map[AffinityKeyV6]AffinityValueV6

// LoadAffinityMap loads affinity map into memory
func LoadAffinityMapV6(m maps.Map) (AffinityMapMemV6, error) {
	ret := make(AffinityMapMemV6)

	if err := m.Open(); err != nil {
		return nil, err
	}

	iterFn := AffinityMapMemV6Iter(ret)

	err := m.Iter(func(k, v []byte) maps.IteratorAction {
		iterFn(k, v)
		return maps.IterNone
	})
	if err != nil {
		ret = nil
	}

	return ret, err
}

// AffinityMapMemIter returns maps.MapIter that loads the provided AffinityMapMem
func AffinityMapMemV6Iter(m AffinityMapMemV6) func(k, v []byte) {
	ks := len(AffinityKeyV6{})
	vs := len(AffinityValueV6{})

	return func(k, v []byte) {
		var key AffinityKeyV6
		copy(key[:ks], k[:ks])

		var val AffinityValueV6
		copy(val[:vs], v[:vs])

		m[key] = val
	}
}

// struct sendrecv4_key {
// 	uint64_t cookie;
// 	uint32_t ip;
// 	uint32_t port;
// };
//
// struct sendrecv4_val {
// 	uint32_t ip;
// 	uint32_t port;
// };

const sendRecvMsgKeyV6Size = 28
const ctNATsMsgKeyV6Size = 38

// SendRecvMsgKeyV6 is the key for SendRecvMsgMap
type SendRecvMsgKeyV6 [sendRecvMsgKeyV6Size]byte

// Cookie returns the socket cookie part of the key that can be used to match
// the socket.
func (k SendRecvMsgKeyV6) Cookie() uint64 {
	return binary.LittleEndian.Uint64(k[0:8])
}

// IP returns the IP address part of the key
func (k SendRecvMsgKeyV6) IP() net.IP {
	return k[8:24]
}

// Port returns port converted to 16-bit host endianness
func (k SendRecvMsgKeyV6) Port() uint16 {
	port := binary.BigEndian.Uint32(k[24:28])
	return uint16(port >> 16)
}

func (k SendRecvMsgKeyV6) String() string {
	return fmt.Sprintf("SendRecvMsgKeyV6{Cookie: 0x%016x, IP: %+v, Port: %+v}", k.Cookie(), k.IP(), k.Port())
}

const sendRecvMsgValueV6Size = 20

// SendRecvMsgValueV6 is the value of SendRecvMsgMap
type SendRecvMsgValueV6 [sendRecvMsgValueV6Size]byte

// IP returns the IP address part of the key
func (v SendRecvMsgValueV6) IP() net.IP {
	return v[0:16]
}

// Port returns port converted to 16-bit host endianness
func (v SendRecvMsgValueV6) Port() uint16 {
	port := binary.BigEndian.Uint32(v[16:20])
	return uint16(port >> 16)
}

func (v SendRecvMsgValueV6) String() string {
	return fmt.Sprintf("SendRecvMsgValueV6{IP: %+v, Port: %+v}", v.IP(), v.Port())
}

// SendRecvMsgMapParameters define SendRecvMsgMap
var SendRecvMsgMapV6Parameters = maps.MapParameters{
	Type:       "lru_hash",
	KeySize:    sendRecvMsgKeyV6Size,
	ValueSize:  sendRecvMsgValueV6Size,
	MaxEntries: 510000,
	Name:       "cali_v6_srmsg",
}

var CTNATsMapV6Parameters = maps.MapParameters{
	Type:       "lru_hash",
	KeySize:    ctNATsMsgKeyV6Size,
	ValueSize:  sendRecvMsgValueV6Size,
	MaxEntries: 10000,
	Name:       "cali_v6_ct_nats",
}

// SendRecvMsgMap tracks reverse translations for sendmsg/recvmsg of
// unconnected UDP
func SendRecvMsgMapV6() maps.Map {
	return maps.NewPinnedMap(SendRecvMsgMapV6Parameters)
}

func AllNATsMsgMapV6() maps.Map {
	return maps.NewPinnedMap(CTNATsMapV6Parameters)
}

// SendRecvMsgMapMem represents affinity map in memory
type SendRecvMsgMapMemV6 map[SendRecvMsgKeyV6]SendRecvMsgValueV6

// LoadSendRecvMsgMap loads affinity map into memory
func LoadSendRecvMsgMapV6(m maps.Map) (SendRecvMsgMapMemV6, error) {
	ret := make(SendRecvMsgMapMemV6)

	iterFn := SendRecvMsgMapMemV6Iter(ret)

	err := m.Iter(func(k, v []byte) maps.IteratorAction {
		iterFn(k, v)
		return maps.IterNone
	})
	if err != nil {
		ret = nil
	}

	return ret, err
}

// SendRecvMsgMapMemIter returns maps.MapIter that loads the provided SendRecvMsgMapMem
func SendRecvMsgMapMemV6Iter(m SendRecvMsgMapMemV6) func(k, v []byte) {
	ks := len(SendRecvMsgKeyV6{})
	vs := len(SendRecvMsgValueV6{})

	return func(k, v []byte) {
		var key SendRecvMsgKeyV6
		copy(key[:ks], k[:ks])

		var val SendRecvMsgValueV6
		copy(val[:vs], v[:vs])

		m[key] = val
	}
}
