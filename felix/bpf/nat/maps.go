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

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/ip"
)

func init() {
	maps.SetSize(FrontendMapParameters.VersionedName(), FrontendMapParameters.MaxEntries)
	maps.SetSize(BackendMapParameters.VersionedName(), BackendMapParameters.MaxEntries)
	maps.SetSize(AffinityMapParameters.VersionedName(), AffinityMapParameters.MaxEntries)
	maps.SetSize(SendRecvMsgMapParameters.VersionedName(), SendRecvMsgMapParameters.MaxEntries)
	maps.SetSize(CTNATsMapParameters.VersionedName(), CTNATsMapParameters.MaxEntries)

	maps.SetSize(FrontendMapV6Parameters.VersionedName(), FrontendMapV6Parameters.MaxEntries)
	maps.SetSize(BackendMapV6Parameters.VersionedName(), BackendMapV6Parameters.MaxEntries)
	maps.SetSize(AffinityMapV6Parameters.VersionedName(), AffinityMapV6Parameters.MaxEntries)
	maps.SetSize(SendRecvMsgMapV6Parameters.VersionedName(), SendRecvMsgMapV6Parameters.MaxEntries)
	maps.SetSize(CTNATsMapV6Parameters.VersionedName(), CTNATsMapV6Parameters.MaxEntries)
}

func SetMapSizes(fsize, bsize, asize int) {
	maps.SetSize(FrontendMapParameters.VersionedName(), fsize)
	maps.SetSize(BackendMapParameters.VersionedName(), bsize)
	maps.SetSize(AffinityMapParameters.VersionedName(), asize)

	maps.SetSize(FrontendMapV6Parameters.VersionedName(), fsize)
	maps.SetSize(BackendMapV6Parameters.VersionedName(), bsize)
	maps.SetSize(AffinityMapV6Parameters.VersionedName(), asize)
}

//	struct calico_nat_v4_key {
//	   uint32_t prefixLen;
//	   uint32_t addr; // NBO
//	   uint16_t port; // HBO
//	   uint8_t protocol;
//	   uint32_t saddr;
//	   uint8_t pad;
//	};
const frontendKeySize = 16

//	struct calico_nat {
//		uint32_t addr;
//		uint16_t port;
//		uint8_t  protocol;
//		uint8_t  pad;
//	};
const frontendAffKeySize = 8

//	struct calico_nat_v4_value {
//	   uint32_t id;
//	   uint32_t count;
//	   uint32_t local;
//	   uint32_t affinity_timeo;
//	   uint32_t flags;
//	};
const frontendValueSize = 20

//	struct calico_nat_secondary_v4_key {
//	  uint32_t id;
//	  uint32_t ordinal;
//	};
const backendKeySize = 8

//	struct calico_nat_dest {
//	   uint32_t addr;
//	   uint16_t port;
//	   uint8_t pad[2];
//	};
const backendValueSize = 8

const BlackHoleCount uint32 = 0xffffffff

// (sizeof(addr) + sizeof(port) + sizeof(proto)) in bits
const ZeroCIDRPrefixLen = 56

var ZeroCIDR = ip.MustParseCIDROrIP("0.0.0.0/0").(ip.V4CIDR)

type FrontendKey [frontendKeySize]byte

type FrontendKeyInterface interface {
	Proto() uint8
	Addr() net.IP
	Port() uint16
	SrcPrefixLen() uint32
	SrcCIDR() ip.CIDR
	AffinitykeyCopy() FrontEndAffinityKeyInterface
	String() string
	AsBytes() []byte
}

func NewNATKey(addr net.IP, port uint16, protocol uint8) FrontendKey {
	return NewNATKeySrc(addr, port, protocol, ZeroCIDR)
}

func NewNATKeyIntf(addr net.IP, port uint16, protocol uint8) FrontendKeyInterface {
	return NewNATKey(addr, port, protocol)
}

func NewNATKeySrc(addr net.IP, port uint16, protocol uint8, cidr ip.CIDR) FrontendKey {
	var k FrontendKey
	prefixlen := ZeroCIDRPrefixLen
	addr = addr.To4()
	if len(addr) != 4 {
		log.WithField("ip", addr).Panic("Bad IP")
	}
	binary.LittleEndian.PutUint32(k[:4], uint32(prefixlen)+uint32(cidr.Prefix()))
	copy(k[4:8], addr)
	binary.LittleEndian.PutUint16(k[8:10], port)
	k[10] = protocol
	copy(k[11:15], cidr.Addr().AsNetIP().To4())
	return k
}

func NewNATKeySrcIntf(addr net.IP, port uint16, protocol uint8, cidr ip.CIDR) FrontendKeyInterface {
	return NewNATKeySrc(addr, port, protocol, cidr)
}

func (k FrontendKey) Proto() uint8 {
	return k[10]
}

func (k FrontendKey) Addr() net.IP {
	return k[4:8]
}

func (k FrontendKey) srcAddr() ip.Addr {
	var addr ip.V4Addr
	copy(addr[:], k[11:15])
	return addr
}

// This function returns the Prefix length of the source CIDR
func (k FrontendKey) SrcPrefixLen() uint32 {
	return k.PrefixLen() - ZeroCIDRPrefixLen
}

func (k FrontendKey) SrcCIDR() ip.CIDR {
	return ip.CIDRFromAddrAndPrefix(k.srcAddr(), int(k.SrcPrefixLen()))
}

func (k FrontendKey) PrefixLen() uint32 {
	return binary.LittleEndian.Uint32(k[0:4])
}

func (k FrontendKey) Port() uint16 {
	return binary.LittleEndian.Uint16(k[8:10])
}

func (k FrontendKey) AsBytes() []byte {
	return k[:]
}

func (k FrontendKey) Affinitykey() []byte {
	return k[4:12]
}

func (k FrontendKey) AffinitykeyCopy() FrontEndAffinityKeyInterface {
	var affkey FrontEndAffinityKey
	copy(affkey[:], k.Affinitykey())
	return affkey
}

func (k FrontendKey) String() string {
	return fmt.Sprintf("NATKey{Proto:%v Addr:%v Port:%v SrcAddr:%v}", k.Proto(), k.Addr(), k.Port(), k.SrcCIDR())
}

func FrontendKeyFromBytes(b []byte) FrontendKeyInterface {
	var k FrontendKey
	copy(k[:], b)
	return k
}

const (
	NATFlgExternalLocal = 0x1
	NATFlgInternalLocal = 0x2
)

var flgTostr = map[int]string{
	NATFlgExternalLocal: "external-local",
	NATFlgInternalLocal: "internal-local",
}

type FrontendValue [frontendValueSize]byte

func NewNATValue(id uint32, count, local, affinityTimeo uint32) FrontendValue {
	var v FrontendValue
	binary.LittleEndian.PutUint32(v[:4], id)
	binary.LittleEndian.PutUint32(v[4:8], count)
	binary.LittleEndian.PutUint32(v[8:12], local)
	binary.LittleEndian.PutUint32(v[12:16], affinityTimeo)
	return v
}

func NewNATValueWithFlags(id uint32, count, local, affinityTimeo, flags uint32) FrontendValue {
	v := NewNATValue(id, count, local, affinityTimeo)
	binary.LittleEndian.PutUint32(v[16:20], flags)
	return v
}

func (v FrontendValue) ID() uint32 {
	return binary.LittleEndian.Uint32(v[:4])
}

func (v FrontendValue) Count() uint32 {
	return binary.LittleEndian.Uint32(v[4:8])
}

func (v FrontendValue) LocalCount() uint32 {
	return binary.LittleEndian.Uint32(v[8:12])
}

func (v FrontendValue) AffinityTimeout() time.Duration {
	secs := binary.LittleEndian.Uint32(v[12:16])
	return time.Duration(secs) * time.Second
}

func (v FrontendValue) Flags() uint32 {
	return binary.LittleEndian.Uint32(v[16:20])
}

func (v FrontendValue) FlagsAsString() string {
	flgs := v.Flags()
	fstr := ""

	for i := 0; i < 32; i++ {
		flg := uint32(1 << i)
		if flgs&flg != 0 {
			fstr += flgTostr[int(flg)]
		}
		flgs &= ^flg
		if flgs == 0 {
			break
		}
		fstr += ", "
	}

	return fstr
}

func (v FrontendValue) String() string {
	return fmt.Sprintf("NATValue{ID:%d,Count:%d,LocalCount:%d,AffinityTimeout:%d,Flags:{%s}}",
		v.ID(), v.Count(), v.LocalCount(), v.AffinityTimeout(), v.FlagsAsString())
}

func (v FrontendValue) AsBytes() []byte {
	return v[:]
}

func FrontendValueFromBytes(b []byte) FrontendValue {
	var v FrontendValue
	copy(v[:], b)
	return v
}

type BackendKey [backendKeySize]byte

func NewNATBackendKey(id, ordinal uint32) BackendKey {
	var v BackendKey
	binary.LittleEndian.PutUint32(v[:4], id)
	binary.LittleEndian.PutUint32(v[4:8], ordinal)
	return v
}

func (v BackendKey) ID() uint32 {
	return binary.LittleEndian.Uint32(v[:4])
}

func (v BackendKey) Count() uint32 {
	return binary.LittleEndian.Uint32(v[4:8])
}

func (v BackendKey) String() string {
	return fmt.Sprintf("NATBackendKey{ID:%d,Ordinal:%d}", v.ID(), v.Count())
}

func (k BackendKey) AsBytes() []byte {
	return k[:]
}

func BackendKeyFromBytes(b []byte) BackendKey {
	var k BackendKey
	copy(k[:], b)
	return k
}

type BackendValue [backendValueSize]byte

type BackendValueInterface interface {
	Addr() net.IP
	Port() uint16
	String() string
	AsBytes() []byte
}

func NewNATBackendValue(addr net.IP, port uint16) BackendValue {
	var k BackendValue
	addr = addr.To4()
	if len(addr) != 4 {
		log.WithField("ip", addr).Panic("Bad IP")
	}
	copy(k[:4], addr)
	binary.LittleEndian.PutUint16(k[4:6], port)
	return k
}

func NewNATBackendValueIntf(addr net.IP, port uint16) BackendValueInterface {
	return NewNATBackendValue(addr, port)
}

func (k BackendValue) Addr() net.IP {
	return k[:4]
}

func (k BackendValue) Port() uint16 {
	return binary.LittleEndian.Uint16(k[4:6])
}

func (k BackendValue) String() string {
	return fmt.Sprintf("NATBackendValue{Addr:%v Port:%v}", k.Addr(), k.Port())
}

func (k BackendValue) AsBytes() []byte {
	return k[:]
}

func BackendValueFromBytes(b []byte) BackendValueInterface {
	var v BackendValue
	copy(v[:], b)
	return v
}

var FrontendMapParameters = maps.MapParameters{
	Type:       "lpm_trie",
	KeySize:    frontendKeySize,
	ValueSize:  frontendValueSize,
	MaxEntries: 64 * 1024,
	Name:       "cali_v4_nat_fe",
	Flags:      unix.BPF_F_NO_PREALLOC,
	Version:    3,
}

func FrontendMap() maps.MapWithExistsCheck {
	return maps.NewPinnedMap(FrontendMapParameters)
}

var BackendMapParameters = maps.MapParameters{
	Type:       "hash",
	KeySize:    backendKeySize,
	ValueSize:  backendValueSize,
	MaxEntries: 256 * 1024,
	Name:       "cali_v4_nat_be",
	Flags:      unix.BPF_F_NO_PREALLOC,
}

func BackendMap() maps.MapWithExistsCheck {
	return maps.NewPinnedMap(BackendMapParameters)
}

// NATMapMem represents FrontendMap loaded into memory
type MapMem map[FrontendKey]FrontendValue

// Equal compares keys and values of the NATMapMem
func (m MapMem) Equal(cmp MapMem) bool {
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
func LoadFrontendMap(m maps.Map) (MapMem, error) {
	ret := make(MapMem)

	if err := m.Open(); err != nil {
		return nil, err
	}

	iterFn := MapMemIter(ret)

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
func MapMemIter(m MapMem) func(k, v []byte) {
	ks := len(FrontendKey{})
	vs := len(FrontendValue{})

	return func(k, v []byte) {
		var key FrontendKey
		copy(key[:ks], k[:ks])

		var val FrontendValue
		copy(val[:vs], v[:vs])

		m[key] = val
	}
}

// BackendMapMem represents a NATBackend loaded into memory
type BackendMapMem map[BackendKey]BackendValue

// Equal compares keys and values of the NATBackendMapMem
func (m BackendMapMem) Equal(cmp BackendMapMem) bool {
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
func LoadBackendMap(m maps.Map) (BackendMapMem, error) {
	ret := make(BackendMapMem)

	if err := m.Open(); err != nil {
		return nil, err
	}

	iterFn := BackendMapMemIter(ret)

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
func BackendMapMemIter(m BackendMapMem) func(k, v []byte) {
	ks := len(BackendKey{})
	vs := len(BackendValue{})

	return func(k, v []byte) {
		var key BackendKey
		copy(key[:ks], k[:ks])

		var val BackendValue
		copy(val[:vs], v[:vs])

		m[key] = val
	}
}

// struct calico_nat_v4_affinity_key {
//    struct calico_nat_v4 nat_key;
// 	  uint32_t client_ip;
// 	  uint32_t padding;
// };

const affinityKeySize = frontendAffKeySize + 8

// AffinityKey is a key into the affinity table that consist of FrontendKey and
// the client's IP
type AffinityKey [affinityKeySize]byte

type AffinityKeyInterface interface {
	ClientIP() net.IP
	FrontendAffinityKey() FrontEndAffinityKeyInterface
	String() string
}

type FrontEndAffinityKey [frontendAffKeySize]byte

type FrontEndAffinityKeyInterface interface {
	Proto() uint8
	Addr() net.IP
	Port() uint16
	AsBytes() []byte
}

func (k FrontEndAffinityKey) AsBytes() []byte {
	return k[:]
}

func (k FrontEndAffinityKey) String() string {
	return fmt.Sprintf("FrontEndAffinityKey{Proto:%v Addr:%v Port:%v}", k.Proto(), k.Addr(), k.Port())
}

func (k FrontEndAffinityKey) Proto() uint8 {
	return k[6]
}

func (k FrontEndAffinityKey) Addr() net.IP {
	return k[0:4]
}

func (k FrontEndAffinityKey) Port() uint16 {
	return binary.LittleEndian.Uint16(k[4:6])
}

// NewAffinityKey create a new AffinityKey from a clientIP and FrontendKey
func NewAffinityKey(clientIP net.IP, fEndKey FrontendKey) AffinityKey {
	var k AffinityKey

	copy(k[:], fEndKey[4:11])

	addr := clientIP.To4()
	if len(addr) != 4 {
		log.WithField("ip", addr).Panic("Bad IP")
	}
	copy(k[frontendAffKeySize:frontendAffKeySize+4], addr)
	return k
}

// ClientIP returns the ClientIP part of the key
func (k AffinityKey) ClientIP() net.IP {
	return k[frontendAffKeySize : frontendAffKeySize+4]
}

// FrontendKey returns the FrontendKey part of the key
func (k AffinityKey) FrontendAffinityKey() FrontEndAffinityKeyInterface {
	var f FrontEndAffinityKey
	copy(f[:], k[:frontendAffKeySize])

	return f
}

func (k AffinityKey) String() string {
	return fmt.Sprintf("AffinityKey{ClientIP:%v %s}", k.ClientIP(), k.FrontendAffinityKey())
}

// AsBytes returns the key as []byte
func (k AffinityKey) AsBytes() []byte {
	return k[:]
}

func AffinityKeyFromBytes(b []byte) AffinityKey {
	var v AffinityKey
	copy(v[:], b)
	return v
}

func AffinityKeyIntfFromBytes(b []byte) AffinityKeyInterface {
	return AffinityKeyFromBytes(b)
}

// struct calico_nat_v4_affinity_val {
//    struct calico_nat_dest;
//    uint64_t ts;
// };

const affinityValueSize = backendValueSize + 8

// AffinityValue represents a backend picked by the affinity and the timestamp
// of its creating
type AffinityValue [affinityValueSize]byte

type AffinityValueInterface interface {
	Timestamp() time.Duration
	Backend() BackendValueInterface
}

// NewAffinityValue creates a value from a timestamp and a backend
func NewAffinityValue(ts uint64, backend BackendValue) AffinityValue {
	var v AffinityValue

	copy(v[:], backend[:])
	binary.LittleEndian.PutUint64(v[backendValueSize:backendValueSize+8], ts)

	return v
}

// Timestamp returns the timestamp of the entry. It is generated by
// bpf_ktime_get_ns which returns the time since the system boot in nanoseconds
// - it is the monotonic clock reading, which is compatible with time operations
// in time package.
func (v AffinityValue) Timestamp() time.Duration {
	nano := binary.LittleEndian.Uint64(v[backendValueSize : backendValueSize+8])
	return time.Duration(nano) * time.Nanosecond
}

// Backend returns the backend the affinity ties the frontend + client to.
func (v AffinityValue) Backend() BackendValueInterface {
	var b BackendValue

	copy(b[:], v[:backendValueSize])

	return b
}

func (v AffinityValue) String() string {
	return fmt.Sprintf("AffinityValue{Timestamp:%d,Backend:%v}", v.Timestamp(), v.Backend())
}

// AsBytes returns the value as []byte
func (v AffinityValue) AsBytes() []byte {
	return v[:]
}

func AffinityValueFromBytes(b []byte) AffinityValue {
	var v AffinityValue
	copy(v[:], b)
	return v
}

func AffinityValueIntfFromBytes(b []byte) AffinityValueInterface {
	return AffinityValueFromBytes(b)
}

// AffinityMapParameters describe the AffinityMap
var AffinityMapParameters = maps.MapParameters{
	Type:       "lru_hash",
	KeySize:    affinityKeySize,
	ValueSize:  affinityValueSize,
	MaxEntries: 64 * 1024,
	Name:       "cali_v4_nat_aff",
}

// AffinityMap returns an instance of an affinity map
func AffinityMap() maps.Map {
	return maps.NewPinnedMap(AffinityMapParameters)
}

// AffinityMapMem represents affinity map in memory
type AffinityMapMem map[AffinityKey]AffinityValue

// LoadAffinityMap loads affinity map into memory
func LoadAffinityMap(m maps.Map) (AffinityMapMem, error) {
	ret := make(AffinityMapMem)

	if err := m.Open(); err != nil {
		return nil, err
	}

	iterFn := AffinityMapMemIter(ret)

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
func AffinityMapMemIter(m AffinityMapMem) func(k, v []byte) {
	ks := len(AffinityKey{})
	vs := len(AffinityValue{})

	return func(k, v []byte) {
		var key AffinityKey
		copy(key[:ks], k[:ks])

		var val AffinityValue
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

const sendRecvMsgKeySize = 16
const ctNATsMsgKeySize = 24

// SendRecvMsgKey is the key for SendRecvMsgMap
type SendRecvMsgKey [sendRecvMsgKeySize]byte

// Cookie returns the socket cookie part of the key that can be used to match
// the socket.
func (k SendRecvMsgKey) Cookie() uint64 {
	return binary.LittleEndian.Uint64(k[0:8])
}

// IP returns the IP address part of the key
func (k SendRecvMsgKey) IP() net.IP {
	return k[8:12]
}

// Port returns port converted to 16-bit host endianness
func (k SendRecvMsgKey) Port() uint16 {
	port := binary.BigEndian.Uint32(k[12:16])
	return uint16(port >> 16)
}

func (k SendRecvMsgKey) String() string {
	return fmt.Sprintf("SendRecvMsgKey{Cookie: 0x%016x, IP: %+v, Port: %+v}", k.Cookie(), k.IP(), k.Port())
}

const sendRecvMsgValueSize = 8

// SendRecvMsgValue is the value of SendRecvMsgMap
type SendRecvMsgValue [sendRecvMsgValueSize]byte

// IP returns the IP address part of the key
func (v SendRecvMsgValue) IP() net.IP {
	return v[0:4]
}

// Port returns port converted to 16-bit host endianness
func (v SendRecvMsgValue) Port() uint16 {
	port := binary.BigEndian.Uint32(v[4:8])
	return uint16(port >> 16)
}

func (v SendRecvMsgValue) String() string {
	return fmt.Sprintf("SendRecvMsgValue{IP: %+v, Port: %+v}", v.IP(), v.Port())
}

// SendRecvMsgMapParameters define SendRecvMsgMap
var SendRecvMsgMapParameters = maps.MapParameters{
	Type:       "lru_hash",
	KeySize:    sendRecvMsgKeySize,
	ValueSize:  sendRecvMsgValueSize,
	MaxEntries: 510000,
	Name:       "cali_v4_srmsg",
}

var CTNATsMapParameters = maps.MapParameters{
	Type:       "lru_hash",
	KeySize:    ctNATsMsgKeySize,
	ValueSize:  sendRecvMsgValueSize,
	MaxEntries: 10000,
	Name:       "cali_v4_ct_nats",
}

// SendRecvMsgMap tracks reverse translations for sendmsg/recvmsg of
// unconnected UDP
func SendRecvMsgMap() maps.Map {
	return maps.NewPinnedMap(SendRecvMsgMapParameters)
}

func AllNATsMsgMap() maps.Map {
	return maps.NewPinnedMap(CTNATsMapParameters)
}

// SendRecvMsgMapMem represents affinity map in memory
type SendRecvMsgMapMem map[SendRecvMsgKey]SendRecvMsgValue

// LoadSendRecvMsgMap loads affinity map into memory
func LoadSendRecvMsgMap(m maps.Map) (SendRecvMsgMapMem, error) {
	ret := make(SendRecvMsgMapMem)

	iterFn := SendRecvMsgMapMemIter(ret)

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
func SendRecvMsgMapMemIter(m SendRecvMsgMapMem) func(k, v []byte) {
	ks := len(SendRecvMsgKey{})
	vs := len(SendRecvMsgValue{})

	return func(k, v []byte) {
		var key SendRecvMsgKey
		copy(key[:ks], k[:ks])

		var val SendRecvMsgValue
		copy(val[:vs], v[:vs])

		m[key] = val
	}
}
