package v2

import (
	"github.com/projectcalico/calico/felix/bpf/maps"
	"golang.org/x/sys/unix"
)

//	struct calico_nat_v4_key {
//	   uint32_t prefixLen;
//	   uint32_t addr; // NBO
//	   uint16_t port; // HBO
//	   uint8_t protocol;
//	   uint32_t saddr;
//	   uint8_t pad;
//	};
const frontendKeySize = 16

//	struct calico_nat_v4_value {
//	   uint32_t id;
//	   uint32_t count;
//	   uint32_t local;
//	   uint32_t affinity_timeo;
//	   uint32_t flags;
//	};
const frontendValueSize = 20

var FrontendMapParameters = maps.MapParameters{
	Type:       "lpm_trie",
	KeySize:    frontendKeySize,
	ValueSize:  frontendValueSize,
	MaxEntries: 64 * 1024,
	Name:       "cali_v4_nat_fe",
	Flags:      unix.BPF_F_NO_PREALLOC,
	Version:    2,
}
