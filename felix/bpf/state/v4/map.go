package v4

import "github.com/projectcalico/calico/felix/bpf/maps"

const expectedSize = 464

var MapParameters = maps.MapParameters{
	Type:       "percpu_array",
	KeySize:    4,
	ValueSize:  expectedSize,
	MaxEntries: 2,
	Name:       "cali_state",
	Version:    4,
}
