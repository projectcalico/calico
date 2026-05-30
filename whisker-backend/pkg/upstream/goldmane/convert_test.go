// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package goldmane

import (
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/goldmane/proto"
	whiskerv1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
)

func TestProtoToFlow_BasicFields(t *testing.T) {
	RegisterTestingT(t)

	flow := &proto.Flow{
		StartTime: 1000,
		EndTime:   2000,
		Key: &proto.FlowKey{
			Action:          proto.Action_Allow,
			SourceName:      "frontend-abc",
			SourceNamespace: "team-a",
			DestName:        "backend-xyz",
			DestNamespace:   "team-b",
			Proto:           "tcp",
			DestPort:        8080,
			Reporter:        proto.Reporter_Src,
		},
		SourceLabels: []string{"app=frontend", "env=prod"},
		DestLabels:   []string{"app=backend"},
		PacketsIn:    12,
		PacketsOut:   14,
		BytesIn:      4321,
		BytesOut:     8765,
	}

	resp := protoToFlow(flow)

	Expect(resp.StartTime.Unix()).To(Equal(int64(1000)))
	Expect(resp.EndTime.Unix()).To(Equal(int64(2000)))
	Expect(resp.Action).To(Equal(whiskerv1.Action(proto.Action_Allow)))
	Expect(resp.SourceName).To(Equal("frontend-abc"))
	Expect(resp.SourceNamespace).To(Equal("team-a"))
	Expect(resp.DestName).To(Equal("backend-xyz"))
	Expect(resp.DestNamespace).To(Equal("team-b"))
	Expect(resp.Protocol).To(Equal("tcp"))
	Expect(resp.DestPort).To(Equal(int64(8080)))
	Expect(resp.Reporter).To(Equal(whiskerv1.Reporter(proto.Reporter_Src)))
	Expect(resp.SourceLabels).To(Equal("app=frontend | env=prod"))
	Expect(resp.DestLabels).To(Equal("app=backend"))
	Expect(resp.PacketsIn).To(Equal(int64(12)))
	Expect(resp.PacketsOut).To(Equal(int64(14)))
	Expect(resp.BytesIn).To(Equal(int64(4321)))
	Expect(resp.BytesOut).To(Equal(int64(8765)))
}

func TestProtoToFlow_Service(t *testing.T) {
	RegisterTestingT(t)

	flow := &proto.Flow{
		Key: &proto.FlowKey{
			DestServiceName:      "api",
			DestServiceNamespace: "team-b",
			DestServicePort:      8080,
			DestServicePortName:  "http",
		},
	}

	resp := protoToFlow(flow)

	Expect(resp.Service).NotTo(BeNil())
	Expect(resp.Service.Name).To(Equal("api"))
	Expect(resp.Service.Namespace).To(Equal("team-b"))
	Expect(resp.Service.Port).To(Equal(int64(8080)))
	Expect(resp.Service.PortName).To(Equal("http"))
}

func TestProtoToFlow_ServiceAbsent(t *testing.T) {
	RegisterTestingT(t)

	resp := protoToFlow(&proto.Flow{Key: &proto.FlowKey{}})
	Expect(resp.Service).To(BeNil())
}

func TestProtoToFlow_NameAndNamespaceSpecialCases(t *testing.T) {
	RegisterTestingT(t)

	flow := &proto.Flow{
		Key: &proto.FlowKey{
			SourceName:      pub,
			SourceNamespace: "",
			DestName:        pvt,
			DestNamespace:   "-",
		},
	}

	resp := protoToFlow(flow)

	// "pub"/"pvt" expand to the public/private network display names; the empty
	// and "-" namespaces are left as-is by protoToFlow (only filter hints remap
	// namespaces to "Global").
	Expect(resp.SourceName).To(Equal(publicNetwork))
	Expect(resp.DestName).To(Equal(privateNetwork))
}

func TestProtoToNamespace(t *testing.T) {
	RegisterTestingT(t)

	Expect(protoToNamespace("")).To(Equal(global))
	Expect(protoToNamespace("-")).To(Equal(global))
	Expect(protoToNamespace("team-a")).To(Equal("team-a"))
}
