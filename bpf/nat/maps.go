// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

	"github.com/projectcalico/felix/bpf"
)

// struct calico_nat_v4_key {
//    uint32_t addr; // NBO
//    uint16_t port; // HBO
//    uint8_t protocol;
//    uint8_t pad;
// };
const frontendKeySize = 8

// struct calico_nat_v4_value {
//    uint32_t id;
//    uint32_t count;
//    uint32_t local;
//    uint32_t affinity_timeo;
// };
const frontendValueSize = 16

// struct calico_nat_secondary_v4_key {
//   uint32_t id;
//   uint32_t ordinal;
// };
const backendKeySize = 8

// struct calico_nat_dest {
//    uint32_t addr;
//    uint16_t port;
//    uint8_t pad[2];
// };
const backendValueSize = 8

type FrontendKey [frontendKeySize]byte

func NewNATKey(addr net.IP, port uint16, protocol uint8) FrontendKey {
	var k FrontendKey
	addr = addr.To4()
	if len(addr) != 4 {
		log.WithField("ip", addr).Panic("Bad IP")
	}
	copy(k[:4], addr)
	binary.LittleEndian.PutUint16(k[4:6], port)
	k[6] = protocol
	return k
}

func (k FrontendKey) Proto() uint8 {
	return k[6]
}

func (k FrontendKey) Addr() net.IP {
	return k[:4]
}

func (k FrontendKey) Port() uint16 {
	return binary.LittleEndian.Uint16(k[4:6])
}

func (k FrontendKey) AsBytes() []byte {
	return k[:]
}

func (k FrontendKey) String() string {
	return fmt.Sprintf("NATKey{Proto:%v Addr:%v Port:%v}", k.Proto(), k.Addr(), k.Port())
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

func (v FrontendValue) String() string {
	return fmt.Sprintf("NATValue{ID:%d,Count:%d,LocalCount:%d,AffinityTimeout:%d}",
		v.ID(), v.Count(), v.LocalCount(), v.AffinityTimeout())
}

func (v FrontendValue) AsBytes() []byte {
	return v[:]
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

type BackendValue [backendValueSize]byte

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

var FrontendMapParameters = bpf.MapParameters{
	Filename:   "/sys/fs/bpf/tc/globals/cali_v4_nat_fe",
	Type:       "hash",
	KeySize:    frontendKeySize,
	ValueSize:  frontendValueSize,
	MaxEntries: 511000,
	Name:       "cali_v4_nat_fe",
	Flags:      unix.BPF_F_NO_PREALLOC,
}

func FrontendMap(mc *bpf.MapContext) bpf.Map {
	return mc.NewPinnedMap(FrontendMapParameters)
}

var BackendMapParameters = bpf.MapParameters{
	Filename:   "/sys/fs/bpf/tc/globals/cali_v4_nat_be",
	Type:       "hash",
	KeySize:    backendKeySize,
	ValueSize:  backendValueSize,
	MaxEntries: 510000,
	Name:       "cali_v4_nat_be",
	Flags:      unix.BPF_F_NO_PREALLOC,
}

func BackendMap(mc *bpf.MapContext) bpf.Map {
	return mc.NewPinnedMap(BackendMapParameters)
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
func LoadFrontendMap(m bpf.Map) (MapMem, error) {
	ret := make(MapMem)

	err := m.Iter(MapMemIter(ret))
	if err != nil {
		ret = nil
	}

	return ret, err
}

// MapMemIter returns bpf.MapIter that loads the provided NATMapMem
func MapMemIter(m MapMem) bpf.MapIter {
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

// NATBackendMapMem represents a NATBackend loaded into memory
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
func LoadBackendMap(m bpf.Map) (BackendMapMem, error) {
	ret := make(BackendMapMem)

	err := m.Iter(BackendMapMemIter(ret))
	if err != nil {
		ret = nil
	}

	return ret, err
}

// BackendMapMemIter returns bpf.MapIter that loads the provided NATBackendMapMem
func BackendMapMemIter(m BackendMapMem) bpf.MapIter {
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
//    struct calico_nat_v4_key nat_key;
// 	  uint32_t client_ip;
// 	  uint32_t padding;
// };

const affinityKeySize = frontendKeySize + 8

// AffinityKey is a key into the affinity table that consist of FrontendKey and
// the client's IP
type AffinityKey [affinityKeySize]byte

// NewAffinityKey create a new AffinityKey from a clientIP and FrontendKey
func NewAffinityKey(clientIP net.IP, fEndKey FrontendKey) AffinityKey {
	var k AffinityKey

	copy(k[:], fEndKey[:])

	addr := clientIP.To4()
	if len(addr) != 4 {
		log.WithField("ip", addr).Panic("Bad IP")
	}
	copy(k[frontendKeySize:frontendKeySize+4], addr)

	return k
}

// ClientIP returns the ClientIP part of the key
func (k AffinityKey) ClientIP() net.IP {
	return k[frontendKeySize : frontendKeySize+4]
}

// FrontendKey returns the FrontendKey part of the key
func (k AffinityKey) FrontendKey() FrontendKey {
	var f FrontendKey
	copy(f[:], k[:frontendKeySize])

	return f
}

func (k AffinityKey) String() string {
	return fmt.Sprintf("AffinityKey{ClientIP:%v %s}", k.ClientIP(), k.FrontendKey())
}

// AsBytes returns the key as []byte
func (k AffinityKey) AsBytes() []byte {
	return k[:]
}

// struct calico_nat_v4_affinity_val {
//    struct calico_nat_dest;
//    uint64_t ts;
// };

const affinityValueSize = backendValueSize + 8

// AffinityValue represents a backend picked by the affinity and the timestamp
// of its creating
type AffinityValue [affinityValueSize]byte

// NewAffinityValue creates a value from a timestamp and a backend
func NewAffinityValue(ts uint64, backend BackendValue) AffinityValue {
	var v AffinityValue

	copy(v[:], backend[:])
	binary.LittleEndian.PutUint64(v[backendValueSize:backendValueSize+8], ts)

	return v
}

// Timestamp returns the timestamp of the entry. It is generated by
// bpf_ktime_get_ns which returns the time since the system boot in nanoseconds
// - it is the monotonic clock reading, whic is compatible with time operations
// in time package.
func (v AffinityValue) Timestamp() time.Duration {
	nano := binary.LittleEndian.Uint64(v[backendValueSize : backendValueSize+8])
	return time.Duration(nano) * time.Nanosecond
}

// Backend returns the backend the affinity ties the frontend + client to.
func (v AffinityValue) Backend() BackendValue {
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

// AffinityMapParameters describe the AffinityMap
var AffinityMapParameters = bpf.MapParameters{
	Filename:   "/sys/fs/bpf/tc/globals/cali_v4_nat_aff",
	Type:       "lru_hash",
	KeySize:    affinityKeySize,
	ValueSize:  affinityValueSize,
	MaxEntries: 510000,
	Name:       "cali_v4_nat_aff",
}

// AffinityMap returns an instance of an affinity map
func AffinityMap(mc *bpf.MapContext) bpf.Map {
	return mc.NewPinnedMap(AffinityMapParameters)
}

// AffinityMapMem represents affinity map in memory
type AffinityMapMem map[AffinityKey]AffinityValue

// LoadAffinityMap loads affinity map into memory
func LoadAffinityMap(m bpf.Map) (AffinityMapMem, error) {
	ret := make(AffinityMapMem)

	err := m.Iter(AffinityMapMemIter(ret))
	if err != nil {
		ret = nil
	}

	return ret, err
}

// AffinityMapMemIter returns bpf.MapIter that loads the provided AffinityMapMem
func AffinityMapMemIter(m AffinityMapMem) bpf.MapIter {
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

// Port returns port converted to 16-bit host endianess
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

// Port returns port converted to 16-bit host endianess
func (v SendRecvMsgValue) Port() uint16 {
	port := binary.BigEndian.Uint32(v[4:8])
	return uint16(port >> 16)
}

func (v SendRecvMsgValue) String() string {
	return fmt.Sprintf("SendRecvMsgValue{IP: %+v, Port: %+v}", v.IP(), v.Port())
}

// SendRecvMsgMapParameters define SendRecvMsgMap
var SendRecvMsgMapParameters = bpf.MapParameters{
	Filename:   "/sys/fs/bpf/tc/globals/cali_v4_srmsg",
	Type:       "lru_hash",
	KeySize:    sendRecvMsgKeySize,
	ValueSize:  sendRecvMsgValueSize,
	MaxEntries: 510000,
	Name:       "cali_v4_srmsg",
}

// SendRecvMsgMap tracks reverse translations for sendmsg/recvmsg of
// unconnected UDP
func SendRecvMsgMap(mc *bpf.MapContext) bpf.Map {
	return mc.NewPinnedMap(SendRecvMsgMapParameters)
}

// SendRecvMsgMapMem represents affinity map in memory
type SendRecvMsgMapMem map[SendRecvMsgKey]SendRecvMsgValue

// LoadSendRecvMsgMap loads affinity map into memory
func LoadSendRecvMsgMap(m bpf.Map) (SendRecvMsgMapMem, error) {
	ret := make(SendRecvMsgMapMem)

	err := m.Iter(SendRecvMsgMapMemIter(ret))
	if err != nil {
		ret = nil
	}

	return ret, err
}

// SendRecvMsgMapMemIter returns bpf.MapIter that loads the provided SendRecvMsgMapMem
func SendRecvMsgMapMemIter(m SendRecvMsgMapMem) bpf.MapIter {
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
