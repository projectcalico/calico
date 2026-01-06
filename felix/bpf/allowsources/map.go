package allowsources

import (
	"encoding/binary"
	"fmt"

	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/ip"
	"golang.org/x/sys/unix"
)


const (
    KeySize = 8
)

var DummyValue = []byte{1, 0, 0, 0}

// uint32 prefixLen
// uint32 addr BE
type AllowSourcesEntry [KeySize]byte

var MapParameters = maps.MapParameters{
	Type:       "lpm_trie",
	KeySize:    KeySize,
	ValueSize:  4,
	MaxEntries: 256 * 1024,
	Name:       "cali_v4_sprefix",
	Flags:      unix.BPF_F_NO_PREALLOC,
}


func Map() maps.Map {
    return maps.NewPinnedMap(MapParameters)
}


type AllowSourcesEntryInterface interface {
    Addr() ip.Addr
    PrefixLen() int
    AsBytes() []byte
}

func (e AllowSourcesEntry) Addr() ip.Addr {
    var addr ip.V4Addr
	copy(addr[:], e[4:8])
	return addr
}

func (e AllowSourcesEntry) PrefixLen() int {
	return int(binary.LittleEndian.Uint32(e[:4]))
}


func (e AllowSourcesEntry) AsBytes() []byte {
	return e[:]
}

func (e AllowSourcesEntry) String() string {
    return fmt.Sprintf("%11s prefix %d", e.Addr(), e.PrefixLen())
}

func MakeAllowSourcesEntry(cidr ip.CIDR) AllowSourcesEntry {
    var entry AllowSourcesEntry
    binary.LittleEndian.PutUint32(entry[:4], uint32(cidr.Prefix()))
    binary.BigEndian.PutUint32(entry[4:], cidr.Addr().(ip.V4Addr).AsUint32())
    return entry
}

func AddAllowedSourceEntry(cidr ip.CIDR) error {
    entry := MakeAllowSourcesEntry(cidr)
    return Map().Update(entry.AsBytes(), DummyValue)
}

type MapMem map[AllowSourcesEntry]struct{}

func MapMemIter(m MapMem) func(k, v []byte) {
	ks := len(AllowSourcesEntry{})

	return func(k, v []byte) {
		var key AllowSourcesEntry
		copy(key[:ks], k[:ks])

		m[key] = struct{}{}
	}
}

func (m MapMem) String() string {
    var out string

    for entry := range m {
        out += entry.String() + "\n"
    }

    return out
}
