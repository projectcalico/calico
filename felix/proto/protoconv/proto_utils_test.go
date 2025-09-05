package protoconv

import (
	"reflect"
	"testing"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
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
