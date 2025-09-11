package protoconv

import (
	"reflect"
	"testing"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/epstatusfile"
)

func TestWorkloadEndpointIDToWorkloadEndpointKey(t *testing.T) {
	tests := []struct {
		name     string
		wepID    *proto.WorkloadEndpointID
		hostname string
		expected *model.WorkloadEndpointKey
	}{
		{
			name:     "Valid workload endpoint ID",
			wepID:    &proto.WorkloadEndpointID{OrchestratorId: "k8s", WorkloadId: "default/testpod1", EndpointId: "eth0"},
			hostname: "cluster-node-0",
			expected: &model.WorkloadEndpointKey{
				Hostname:       "cluster-node-0",
				OrchestratorID: "k8s",
				WorkloadID:     "default/testpod1",
				EndpointID:     "eth0",
			},
		},
		{
			name:     "Nil ID",
			wepID:    nil,
			hostname: "",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WorkloadEndpointIDToWorkloadEndpointKey(tt.wepID, tt.hostname)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Fatalf("expected %+v, got %+v", tt.expected, got)
			}
		})
	}
}

func TestWorkloadEndpointToWorkloadEndpointStatus(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		if got := WorkloadEndpointToWorkloadEndpointStatus(nil); got != nil {
			t.Fatalf("expected nil, got %+v", got)
		}
	})

	t.Run("happy path with bgp peer and nets", func(t *testing.T) {
		ep := &proto.WorkloadEndpoint{
			Name:     "cali12345",
			Mac:      "aa:bb:cc:dd:ee:ff",
			Ipv4Nets: []string{"10.0.0.1/32"},
			Ipv6Nets: []string{"fd00::1/128"},
			LocalBgpPeer: &proto.LocalBGPPeer{
				BgpPeerName: "node-1",
			},
		}
		expected := &epstatusfile.WorkloadEndpointStatus{
			IfaceName:   "cali12345",
			Mac:         "aa:bb:cc:dd:ee:ff",
			Ipv4Nets:    []string{"10.0.0.1/32"},
			Ipv6Nets:    []string{"fd00::1/128"},
			BGPPeerName: "node-1",
		}
		got := WorkloadEndpointToWorkloadEndpointStatus(ep)
		if !reflect.DeepEqual(got, expected) {
			t.Fatalf("expected %+v, got %+v", expected, got)
		}
	})

	t.Run("zero-length slices are normalised to nil", func(t *testing.T) {
		ep := &proto.WorkloadEndpoint{
			Name:     "cali67890",
			Mac:      "11:22:33:44:55:66",
			Ipv4Nets: []string{},
			Ipv6Nets: []string{},
		}
		expected := &epstatusfile.WorkloadEndpointStatus{
			IfaceName:   "cali67890",
			Mac:         "11:22:33:44:55:66",
			Ipv4Nets:    nil,
			Ipv6Nets:    nil,
			BGPPeerName: "",
		}
		got := WorkloadEndpointToWorkloadEndpointStatus(ep)
		if !reflect.DeepEqual(got, expected) {
			t.Fatalf("expected %+v, got %+v", expected, got)
		}
	})

	t.Run("mixed nets and no bgp peer", func(t *testing.T) {
		ep := &proto.WorkloadEndpoint{
			Name:     "cali24680",
			Mac:      "de:ad:be:ef:00:01",
			Ipv4Nets: []string{"192.168.0.10/32"},
			Ipv6Nets: []string{},
			// LocalBgpPeer nil
		}
		expected := &epstatusfile.WorkloadEndpointStatus{
			IfaceName:   "cali24680",
			Mac:         "de:ad:be:ef:00:01",
			Ipv4Nets:    []string{"192.168.0.10/32"},
			Ipv6Nets:    nil,
			BGPPeerName: "",
		}
		got := WorkloadEndpointToWorkloadEndpointStatus(ep)
		if !reflect.DeepEqual(got, expected) {
			t.Fatalf("expected %+v, got %+v", expected, got)
		}
	})
}
