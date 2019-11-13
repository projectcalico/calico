// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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

package conntrack

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/felix/bpf"
)

// struct calico_ct_key {
//   uint32_t protocol;
//   __be32 addr_a, addr_b; // NBO
//   uint16_t port_a, port_b; // HBO
// };
const conntrackKeySize = 16
const conntrackValueSize = 48

type Key [conntrackKeySize]byte

func (k Key) AsBytes() []byte {
	return k[:]
}

func (k Key) Proto() uint8 {
	return uint8(binary.LittleEndian.Uint32(k[:4]))
}

func (k Key) AddrA() net.IP {
	return k[4:8]
}

func (k Key) PortA() uint16 {
	return binary.LittleEndian.Uint16(k[12:14])
}

func (k Key) AddrB() net.IP {
	return k[8:12]
}

func (k Key) PortB() uint16 {
	return binary.LittleEndian.Uint16(k[14:16])
}

func (k Key) String() string {
	return fmt.Sprintf("ConntrackKey{proto=%v %v:%v <-> %v:%v}",
		k.Proto(), k.AddrA(), k.PortA(), k.AddrB(), k.PortB())
}

func MakeKey(proto uint8, ipA net.IP, portA uint16, ipB net.IP, portB uint16) Key {
	var k Key
	binary.LittleEndian.PutUint32(k[:4], uint32(proto))
	copy(k[4:8], ipA)
	copy(k[8:12], ipB)
	binary.LittleEndian.PutUint16(k[12:14], portA)
	binary.LittleEndian.PutUint16(k[14:16], portB)
	return k
}

// struct calico_ct_value {
//  __u64 created;
//  __u64 last_seen; // 8
//  __u8 type;     // 16
//
//  // Important to use explicit padding, otherwise the compiler can decide
//  // not to zero the padding bytes, which upsets the verifier.  Worse than
//  // that, debug logging often prevents such optimisation resulting in
//  // failures when debug logging is compiled out only :-).
//  __u8 pad0[7];
//  union {
//    // CALI_CT_TYPE_NORMAL and CALI_CT_TYPE_NAT_REV.
//    struct {
//      struct calico_ct_leg a_to_b; // 24
//      struct calico_ct_leg b_to_a; // 32
//
//      // CALI_CT_TYPE_NAT_REV only.
//      __u32 orig_dst;                    // 40
//      __u16 orig_port;                   // 44
//      __u8 pad1[2];                      // 46
//    };
//
//    // CALI_CT_TYPE_NAT_FWD; key for the CALI_CT_TYPE_NAT_REV entry.
//    struct {
//      struct calico_ct_key nat_rev_key;  // 24
//      __u8 pad2[8];
//    };
//  };
// };
type Entry [conntrackValueSize]byte

func (e Entry) Created() int64 {
	return int64(binary.LittleEndian.Uint64(e[:8]))
}

func (e Entry) LastSeen() int64 {
	return int64(binary.LittleEndian.Uint64(e[8:16]))
}

func (e Entry) Type() uint8 {
	return uint8(e[16])
}

const (
	ValueTypeNormal uint8 = iota
	ValueTypeNATForward
	ValueTypeNATReverse
)

func (e Entry) ReverseNATKey() Key {
	var ret Key

	l := len(Key{})
	copy(ret[:l], e[24:24+l])

	return ret
}

type Leg struct {
	Seqno       uint32
	SynSeen     bool
	AckSeen     bool
	FinSeen     bool
	RstSeen     bool
	Whitelisted bool
	Opener      bool
}

func (leg Leg) Flags() uint32 {
	var flags uint32
	if leg.SynSeen {
		flags |= 1
	}
	if leg.AckSeen {
		flags |= 1 << 1
	}
	if leg.FinSeen {
		flags |= 1 << 2
	}
	if leg.RstSeen {
		flags |= 1 << 3
	}
	if leg.Whitelisted {
		flags |= 1 << 4
	}
	if leg.Opener {
		flags |= 1 << 5
	}
	return flags
}

func bitSet(bits uint32, bit uint8) bool {
	return (bits & (1 << bit)) != 0
}

func readConntrackLeg(b []byte) Leg {
	bits := binary.LittleEndian.Uint32(b[4:8])
	return Leg{
		Seqno:       binary.BigEndian.Uint32(b[0:4]),
		SynSeen:     bitSet(bits, 0),
		AckSeen:     bitSet(bits, 1),
		FinSeen:     bitSet(bits, 2),
		RstSeen:     bitSet(bits, 3),
		Whitelisted: bitSet(bits, 4),
		Opener:      bitSet(bits, 5),
	}
}

type EntryData struct {
	A2B      Leg
	B2A      Leg
	OrigDst  net.IP
	OrigPort uint16
}

func (e Entry) Data() EntryData {
	ip := e[40:44]
	return EntryData{
		A2B:      readConntrackLeg(e[24:32]),
		B2A:      readConntrackLeg(e[32:40]),
		OrigDst:  net.IPv4(ip[0], ip[1], ip[2], ip[3]),
		OrigPort: binary.LittleEndian.Uint16(e[44:46]),
	}
}

func (e Entry) String() string {
	ret := fmt.Sprintf("Entry{Type:%d, Created:%d, LastSeen:%d, ", e.Type(), e.Created(), e.LastSeen())

	switch e.Type() {
	case ValueTypeNATForward:
		ret += fmt.Sprintf("REVKey : %s", e.ReverseNATKey().String())
	case ValueTypeNormal, ValueTypeNATReverse:
		ret += fmt.Sprintf("Data: %+v", e.Data())
	default:
		ret += "TYPE INVALID"
	}

	return ret + "}"
}

var MapParams = bpf.MapParameters{
	Filename:   "/sys/fs/bpf/tc/globals/calico_ct_map_v4",
	Type:       "hash",
	KeySize:    conntrackKeySize,
	ValueSize:  conntrackValueSize,
	MaxEntries: 512000,
	Name:       "calico_ct_map_v4",
	Flags:      unix.BPF_F_NO_PREALLOC,
}

func Map() bpf.Map {
	return bpf.NewPinnedMap(MapParams)
}

// KTimeNanos returns a nanosecond timestamp that is comparable with the ones generated by BPF.
func KTimeNanos() int64 {
	var ts unix.Timespec
	err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	if err != nil {
		log.WithError(err).Panic("Failed to read system clock")
	}
	return ts.Nano()
}

type Timeouts struct {
	CreationGracePeriod time.Duration

	TCPPreEstablished time.Duration
	TCPEstablished    time.Duration
	TCPFinsSeen       time.Duration
	TCPResetSeen      time.Duration

	UDPLastSeen time.Duration

	ICMPLastSeen time.Duration
}

type LivenessScanner struct {
	timeouts Timeouts
	ctMap    bpf.Map
	NowNanos func() int64
}

func NewLivenessScanner(timeouts Timeouts, ctMap bpf.Map) *LivenessScanner {
	return &LivenessScanner{
		timeouts: timeouts,
		ctMap:    ctMap,
		NowNanos: KTimeNanos,
	}
}

const (
	ProtoICMP = 1
	ProtoTCP  = 6
	ProtoUDP  = 17
)

func (l *LivenessScanner) Scan() {
	err := l.ctMap.Iter(func(k, v []byte) {
		ctKey := keyFromBytes(k)
		ctVal := entryFromBytes(v)
		log.WithFields(log.Fields{
			"key":   ctKey,
			"entry": ctVal,
		}).Debug("Examining conntrack entry")

		now := l.NowNanos()

		switch ctVal.Type() {
		case ValueTypeNATForward:
			// Look up the reverse entry, where we do the book-keeping.
			revEntryBytes, err := l.ctMap.Get(ctVal.ReverseNATKey().AsBytes())
			if err != nil && bpf.IsNotExists(err) {
				// Forward entry exists but no reverse entry (and the grace period has expired).
				log.Info("Found a forward NAT conntrack entry with no reverse entry, removing...")
				err := l.ctMap.Delete(k)
				if err != nil && !bpf.IsNotExists(err) {
					log.WithError(err).Warn("Failed to delete conntrack entry.")
				}
				return
			} else if err != nil {
				log.WithError(err).Warn("Failed to look up conntrack entry.")
				return
			}
			revEntry := entryFromBytes(revEntryBytes)
			if reason, expired := l.EntryExpired(now, ctKey.Proto(), revEntry); expired {
				log.WithField("reason", reason).Debug("Deleting expired conntrack forward-NAT entry")
				err := l.ctMap.Delete(k)
				if err != nil && !bpf.IsNotExists(err) {
					log.WithError(err).Warn("Failed to delete expired conntrack forward-NAT entry.")
				}
				err = l.ctMap.Delete(ctVal.ReverseNATKey().AsBytes())
				if err != nil && !bpf.IsNotExists(err) {
					log.WithError(err).Warn("Failed to delete expired conntrack reverse-NAT entry.")
				}
			}
		case ValueTypeNATReverse:
			if reason, expired := l.EntryExpired(now, ctKey.Proto(), ctVal); expired {
				log.WithField("reason", reason).Debug("Deleting expired conntrack reverse-NAT entry")
				err := l.ctMap.Delete(k)
				if err != nil && !bpf.IsNotExists(err) {
					log.WithError(err).Warn("Failed to delete expired conntrack forward-NAT entry.")
				}
				// TODO Handle forward entry.
			}
		case ValueTypeNormal:
			if reason, expired := l.EntryExpired(now, ctKey.Proto(), ctVal); expired {
				log.WithField("reason", reason).Debug("Deleting expired normal conntrack entry")
				err := l.ctMap.Delete(k)
				if err != nil && !bpf.IsNotExists(err) {
					log.WithError(err).Warn("Failed to delete expired conntrack forward-NAT entry.")
				}
			}
		default:
			log.WithField("type", ctVal.Type()).Warn("Unknown conntrack entry type!")
		}
	})
	if err != nil {
		log.WithError(err).Warn("Failed to iterate over conntrack map")
	}
}

func (l *LivenessScanner) EntryExpired(nowNanos int64, proto uint8, entry Entry) (reason string, expired bool) {
	sinceCreation := time.Duration(nowNanos - entry.Created())
	if sinceCreation < l.timeouts.CreationGracePeriod {
		log.Debug("Conntrack entry in creation grace period. Ignoring.")
		return
	}

	age := time.Duration(nowNanos - entry.LastSeen())
	switch proto {
	case ProtoTCP:
		data := entry.Data()
		rstSeen := data.A2B.RstSeen || data.B2A.RstSeen
		if rstSeen && age > l.timeouts.TCPResetSeen {
			return "RST seen", true
		}
		finsSeen := data.A2B.FinSeen && data.B2A.FinSeen
		if finsSeen && age > l.timeouts.TCPFinsSeen {
			// Both legs have been finished, tear down.
			return "FINs seen", true
		}
		established := data.A2B.SynSeen && data.A2B.AckSeen && data.B2A.SynSeen && data.B2A.AckSeen
		if established {
			if age > l.timeouts.TCPEstablished {
				return "no traffic on established flow for too long", true
			}
		} else {
			if age > l.timeouts.TCPPreEstablished {
				return "no traffic on pre-established flow for too long", true
			}
		}
		return "", false
	case ProtoICMP:
		if age > l.timeouts.ICMPLastSeen {
			return "no traffic on ICMP flow for too long", true
		}
	default:
		// FIXME separate timeouts for non-UDP IP traffic?
		if age > l.timeouts.UDPLastSeen {
			return "no traffic on UDP flow for too long", true
		}
	}
	return "", false
}

func keyFromBytes(k []byte) Key {
	var ctKey Key
	if len(k) != len(ctKey) {
		log.Panic("Key has unexpected length")
	}
	copy(ctKey[:], k[:])
	return ctKey
}

func entryFromBytes(v []byte) Entry {
	var ctVal Entry
	if len(v) != len(ctVal) {
		log.Panic("Value has unexpected length")
	}
	copy(ctVal[:], v[:])
	return ctVal
}
