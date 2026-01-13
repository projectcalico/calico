package allowsources

import (
	"encoding/binary"

	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/ip"
	"golang.org/x/sys/unix"
)


const AllowSourcesEntryV6Size = 24

type AllowSourcesEntryV6 [AllowSourcesEntryV6Size]byte

var MapV6Parameters = maps.MapParameters{
	Type:       "lpm_trie",
	KeySize:    AllowSourcesEntryV6Size,
	ValueSize:  4,
	MaxEntries: 1024 * 1024,
	Name:       "cali_v6_sprefix",
	Flags:      unix.BPF_F_NO_PREALLOC,
}

func MapV6() maps.Map {
    return maps.NewPinnedMap(MapV6Parameters)
}

func (e AllowSourcesEntryV6) Addr() ip.Addr {
    var addr ip.V6Addr
    copy(addr[:], e[8:24])
    return addr
}

func (e AllowSourcesEntryV6) PrefixLen() int {
    return int(binary.LittleEndian.Uint32(e[:4]))
}

func (e AllowSourcesEntryV6) IfIndex() int {
    return int(binary.LittleEndian.Uint32(e[4:8]))
}

func (e AllowSourcesEntryV6) AsBytes() []byte {
    return e[:]
}

func MakeAllowSourcesEntryV6(cidr ip.CIDR, ifindex int) AllowSourcesEntryV6 {
    var entry AllowSourcesEntryV6
    ipv6 := cidr.Addr().(ip.V6Addr)
    binary.LittleEndian.PutUint32(entry[:4], uint32(cidr.Prefix()))
    binary.LittleEndian.PutUint32(entry[4:8], uint32(ifindex))
    copy(entry[8:24], ipv6[:])
    return entry
}
