// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package v1

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/projectcalico/calico/goldmane/proto"
)

func TestProtoToFlow_WithSourceIP(t *testing.T) {
	// Create a proto flow with source IP and port
	protoFlow := &proto.Flow{
		Key: &proto.FlowKey{
			SourceName:      "web-app",
			SourceNamespace: "production",
			SourceType:      proto.EndpointType_WorkloadEndpoint,
			SourceIp:        "10.42.0.5",
			SourcePort:      45678,
			DestName:        "database",
			DestNamespace:   "production",
			DestType:        proto.EndpointType_WorkloadEndpoint,
			DestPort:        5432,
			Proto:           "TCP",
			Reporter:        proto.Reporter_Src,
			Action:          proto.Action_Allow,
			Policies:        &proto.PolicyTrace{},
		},
		StartTime:    1234567890,
		EndTime:      1234567900,
		SourceLabels: []string{"app=web", "tier=frontend"},
		DestLabels:   []string{"app=db", "tier=backend"},
		PacketsIn:    100,
		PacketsOut:   150,
		BytesIn:      50000,
		BytesOut:     75000,
	}

	// Convert to API flow response
	flowResp := protoToFlow(protoFlow)

	// Verify source IP and port are included
	assert.Equal(t, "10.42.0.5", flowResp.SourceIP)
	assert.Equal(t, int64(45678), flowResp.SourcePort)
	
	// Verify other fields are still converted correctly
	assert.Equal(t, "web-app", flowResp.SourceName)
	assert.Equal(t, "production", flowResp.SourceNamespace)
	assert.Equal(t, int64(5432), flowResp.DestPort)
	assert.Equal(t, "TCP", flowResp.Protocol)
}

func TestProtoToFlow_EmptySourceIP(t *testing.T) {
	// Test with empty source IP (for backward compatibility)
	protoFlow := &proto.Flow{
		Key: &proto.FlowKey{
			SourceName:      "unknown",
			SourceNamespace: "",
			SourceType:      proto.EndpointType_Network,
			SourceIp:        "", // Empty IP
			SourcePort:      0,  // No port
			DestName:        "service",
			DestNamespace:   "default",
			DestType:        proto.EndpointType_WorkloadEndpoint,
			DestPort:        443,
			Proto:           "TCP",
			Reporter:        proto.Reporter_Dst,
			Action:          proto.Action_Allow,
			Policies:        &proto.PolicyTrace{},
		},
		StartTime: 1234567890,
		EndTime:   1234567900,
	}

	// Convert to API flow response
	flowResp := protoToFlow(protoFlow)

	// Verify empty source IP is handled correctly
	assert.Equal(t, "", flowResp.SourceIP)
	assert.Equal(t, int64(0), flowResp.SourcePort)
}