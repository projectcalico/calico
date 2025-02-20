package calc

import "github.com/projectcalico/calico/libcalico-go/lib/backend/model"

type EndpointMap[T any] struct {
}

func (m *EndpointMap[T]) Put(k model.Key, v T) {
	switch k.(type) {
	case model.WorkloadEndpointKey:

	}
}
