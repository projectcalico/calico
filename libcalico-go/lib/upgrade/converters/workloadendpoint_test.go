// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package converters_test

import (
	cnet "net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/api/pkg/lib/numorstring"

	apiv1 "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/v1/unversioned"
	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/upgrade/converters"
)

var _ = DescribeTable("v1->v3 workload endpoint conversion tests",
	func(v1API unversioned.Resource, v1KVP *model.KVPair, v3API libapiv3.WorkloadEndpoint) {
		w := converters.WorkloadEndpoint{}

		// Test and assert v1 API to v1 backend logic.
		v1KVPResult, err := w.APIV1ToBackendV1(v1API)
		Expect(err).NotTo(HaveOccurred())

		// Metadata to Key.
		Expect(v1KVPResult.Key.(model.WorkloadEndpointKey).Hostname).To(Equal(v1KVP.Key.(model.WorkloadEndpointKey).Hostname))
		Expect(v1KVPResult.Key.(model.WorkloadEndpointKey).OrchestratorID).To(Equal(v1KVP.Key.(model.WorkloadEndpointKey).OrchestratorID))
		Expect(v1KVPResult.Key.(model.WorkloadEndpointKey).WorkloadID).To(Equal(v1KVP.Key.(model.WorkloadEndpointKey).WorkloadID))
		Expect(v1KVPResult.Key.(model.WorkloadEndpointKey).EndpointID).To(Equal(v1KVP.Key.(model.WorkloadEndpointKey).EndpointID))
		// Spec to Value.
		Expect(*v1KVPResult.Value.(*model.WorkloadEndpoint)).To(Equal(*v1KVP.Value.(*model.WorkloadEndpoint)))

		// Test and assert v1 backend to v3 API logic.
		v3APIResult, err := w.BackendV1ToAPIV3(v1KVP)
		Expect(err).NotTo(HaveOccurred())
		Expect(v3APIResult.(*libapiv3.WorkloadEndpoint).ObjectMeta.Name).To(Equal(v3API.ObjectMeta.Name))
		Expect(v3APIResult.(*libapiv3.WorkloadEndpoint).ObjectMeta.Labels).To(Equal(v3API.ObjectMeta.Labels))
		Expect(v3APIResult.(*libapiv3.WorkloadEndpoint).Spec).To(Equal(v3API.Spec))
	},
	Entry("fully populated WEP",
		&apiv1.WorkloadEndpoint{
			Metadata: apiv1.WorkloadEndpointMetadata{
				Name:             "eth0",
				Workload:         "default.frontend-5gs43",
				Orchestrator:     "k8s",
				Node:             "TestNode",
				ActiveInstanceID: "1337495556942031415926535",
				Labels:           makeLabelsV1(),
			},
			Spec: apiv1.WorkloadEndpointSpec{
				IPNetworks:                 []net.IPNet{net.MustParseNetwork("10.0.0.1/32"), net.MustParseNetwork("2001::/128")},
				IPNATs:                     makeIPNATv1(),
				IPv4Gateway:                net.ParseIP("10.0.0.254"),
				IPv6Gateway:                net.ParseIP("2001::"),
				Profiles:                   makeProfilesV1(),
				InterfaceName:              "cali1234",
				MAC:                        makeMac(),
				Ports:                      makeEndpointPortsV1(),
				AllowSpoofedSourcePrefixes: []net.IPNet{net.MustParseNetwork("8.8.8.8/32")},
			},
		},
		&model.KVPair{
			Key: model.WorkloadEndpointKey{
				Hostname:       "TestNode",
				OrchestratorID: "k8s",
				WorkloadID:     "default.frontend-5gs43",
				EndpointID:     "eth0",
			},
			Value: &model.WorkloadEndpoint{
				Labels:                     makeLabelsV1(),
				ActiveInstanceID:           "1337495556942031415926535",
				State:                      "active",
				Name:                       "cali1234",
				Mac:                        makeMac(),
				ProfileIDs:                 makeProfilesV1(),
				IPv4Nets:                   []net.IPNet{net.MustParseNetwork("10.0.0.1/32")},
				IPv6Nets:                   []net.IPNet{net.MustParseNetwork("2001::/128")},
				IPv4NAT:                    makeIPv4NATKvp(),
				IPv6NAT:                    makeIPv6NATKvp(),
				IPv4Gateway:                net.ParseIP("10.0.0.254"),
				IPv6Gateway:                net.ParseIP("2001::"),
				Ports:                      makeEndpointPortsKvp(),
				AllowSpoofedSourcePrefixes: []net.IPNet{net.MustParseNetwork("8.8.8.8/32")},
			},
		},
		libapiv3.WorkloadEndpoint{
			ObjectMeta: v1.ObjectMeta{
				Name:   "testnode-k8s-frontend--5gs43-eth0",
				Labels: makeLabelsV3(),
			},
			Spec: libapiv3.WorkloadEndpointSpec{
				Orchestrator:               "k8s",
				Node:                       "testnode",
				Pod:                        "frontend-5gs43",
				Endpoint:                   "eth0",
				ContainerID:                "1337495556942031415926535",
				IPNetworks:                 []string{"10.0.0.1/32", "2001::/128"},
				IPNATs:                     makeIPNATv3(),
				IPv4Gateway:                "10.0.0.254",
				IPv6Gateway:                "2001::",
				Profiles:                   makeProfilesV3(),
				InterfaceName:              "cali1234",
				MAC:                        "02:42:7d:c6:f0:80",
				Ports:                      makeEndpointPortsV3(),
				AllowSpoofedSourcePrefixes: []string{"8.8.8.8/32"},
			},
		},
	),
	Entry("IPv4 only WEP",
		&apiv1.WorkloadEndpoint{
			Metadata: apiv1.WorkloadEndpointMetadata{
				Name:             "eth0",
				Workload:         "default.frontend-5gs43",
				Orchestrator:     "k8s",
				Node:             "TestNode",
				ActiveInstanceID: "1337495556942031415926535",
				Labels:           makeLabelsV1(),
			},
			Spec: apiv1.WorkloadEndpointSpec{
				IPNetworks: []net.IPNet{net.MustParseNetwork("10.0.0.1/32")},
				IPNATs: []apiv1.IPNAT{
					{
						InternalIP: net.MustParseIP("10.0.0.1"),
						ExternalIP: net.MustParseIP("172.0.0.1"),
					},
				},
				IPv4Gateway:   net.ParseIP("10.0.0.254"),
				Profiles:      makeProfilesV1(),
				InterfaceName: "cali1234",
				MAC:           makeMac(),
				Ports:         makeEndpointPortsV1(),
			},
		},
		&model.KVPair{
			Key: model.WorkloadEndpointKey{
				Hostname:       "TestNode",
				OrchestratorID: "k8s",
				WorkloadID:     "default.frontend-5gs43",
				EndpointID:     "eth0",
			},
			Value: &model.WorkloadEndpoint{
				Labels:           makeLabelsV1(),
				ActiveInstanceID: "1337495556942031415926535",
				State:            "active",
				Name:             "cali1234",
				Mac:              makeMac(),
				ProfileIDs:       makeProfilesV1(),
				IPv4Nets:         []net.IPNet{net.MustParseNetwork("10.0.0.1/32")},
				IPv6Nets:         []net.IPNet{},
				IPv4NAT:          makeIPv4NATKvp(),
				IPv6NAT:          []model.IPNAT{},
				IPv4Gateway:      net.ParseIP("10.0.0.254"),
				Ports:            makeEndpointPortsKvp(),
			},
		},
		libapiv3.WorkloadEndpoint{
			ObjectMeta: v1.ObjectMeta{
				Name:   "testnode-k8s-frontend--5gs43-eth0",
				Labels: makeLabelsV3(),
			},
			Spec: libapiv3.WorkloadEndpointSpec{
				Orchestrator: "k8s",
				Node:         "testnode",
				Pod:          "frontend-5gs43",
				ContainerID:  "1337495556942031415926535",
				Endpoint:     "eth0",
				IPNetworks:   []string{"10.0.0.1/32"},
				IPNATs: []libapiv3.IPNAT{{
					InternalIP: "10.0.0.1",
					ExternalIP: "172.0.0.1",
				}},
				IPv4Gateway:   "10.0.0.254",
				Profiles:      makeProfilesV3(),
				InterfaceName: "cali1234",
				MAC:           "02:42:7d:c6:f0:80",
				Ports:         makeEndpointPortsV3(),
			},
		},
	),
	Entry("IPv6 only WEP",
		&apiv1.WorkloadEndpoint{
			Metadata: apiv1.WorkloadEndpointMetadata{
				Name:             "eth0",
				Workload:         "default.frontend-5gs43",
				Orchestrator:     "k8s",
				Node:             "TestNode",
				ActiveInstanceID: "133749555694203141592653c",
				Labels:           makeLabelsV1(),
			},
			Spec: apiv1.WorkloadEndpointSpec{
				IPNetworks: []net.IPNet{net.MustParseNetwork("2001::/128")},
				IPNATs: []apiv1.IPNAT{
					{
						InternalIP: net.MustParseIP("2001::"),
						ExternalIP: net.MustParseIP("2002::"),
					},
				},
				IPv6Gateway:   net.ParseIP("2001::"),
				Profiles:      makeProfilesV1(),
				InterfaceName: "cali1234",
				MAC:           makeMac(),
				Ports:         makeEndpointPortsV1(),
			},
		},
		&model.KVPair{
			Key: model.WorkloadEndpointKey{
				Hostname:       "TestNode",
				OrchestratorID: "k8s",
				WorkloadID:     "default.frontend-5gs43",
				EndpointID:     "eth0",
			},
			Value: &model.WorkloadEndpoint{
				Labels:           makeLabelsV1(),
				ActiveInstanceID: "133749555694203141592653c",
				State:            "active",
				Name:             "cali1234",
				Mac:              makeMac(),
				ProfileIDs:       makeProfilesV1(),
				IPv4Nets:         []net.IPNet{},
				IPv6Nets:         []net.IPNet{net.MustParseNetwork("2001::/128")},
				IPv4NAT:          []model.IPNAT{},
				IPv6NAT:          makeIPv6NATKvp(),
				IPv6Gateway:      net.ParseIP("2001::"),
				Ports:            makeEndpointPortsKvp(),
			},
		},
		libapiv3.WorkloadEndpoint{
			ObjectMeta: v1.ObjectMeta{
				Name:   "testnode-k8s-frontend--5gs43-eth0",
				Labels: makeLabelsV3(),
			},
			Spec: libapiv3.WorkloadEndpointSpec{
				Orchestrator: "k8s",
				Node:         "testnode",
				Pod:          "frontend-5gs43",
				ContainerID:  "133749555694203141592653c",
				Endpoint:     "eth0",
				IPNetworks:   []string{"2001::/128"},
				IPNATs: []libapiv3.IPNAT{{
					InternalIP: "2001::",
					ExternalIP: "2002::",
				}},
				IPv6Gateway:   "2001::",
				Profiles:      makeProfilesV3(),
				InterfaceName: "cali1234",
				MAC:           "02:42:7d:c6:f0:80",
				Ports:         makeEndpointPortsV3(),
			},
		},
	),
	Entry("WEP missing labels",
		&apiv1.WorkloadEndpoint{
			Metadata: apiv1.WorkloadEndpointMetadata{
				Name:             "eth0",
				Workload:         "default.frontend-5gs43",
				Orchestrator:     "k8s",
				Node:             "TestNode",
				ActiveInstanceID: "133749555694203141592653a",
				Labels:           map[string]string{},
			},
			Spec: apiv1.WorkloadEndpointSpec{
				IPNetworks:    []net.IPNet{net.MustParseNetwork("10.0.0.1/32"), net.MustParseNetwork("2001::/128")},
				IPNATs:        makeIPNATv1(),
				IPv4Gateway:   net.ParseIP("10.0.0.254"),
				IPv6Gateway:   net.ParseIP("2001::"),
				Profiles:      makeProfilesV1(),
				InterfaceName: "cali1234",
				MAC:           makeMac(),
				Ports:         makeEndpointPortsV1(),
			},
		},
		&model.KVPair{
			Key: model.WorkloadEndpointKey{
				Hostname:       "TestNode",
				OrchestratorID: "k8s",
				WorkloadID:     "default.frontend-5gs43",
				EndpointID:     "eth0",
			},
			Value: &model.WorkloadEndpoint{
				Labels:           map[string]string{},
				ActiveInstanceID: "133749555694203141592653a",
				State:            "active",
				Name:             "cali1234",
				Mac:              makeMac(),
				ProfileIDs:       makeProfilesV1(),
				IPv4Nets:         []net.IPNet{net.MustParseNetwork("10.0.0.1/32")},
				IPv6Nets:         []net.IPNet{net.MustParseNetwork("2001::/128")},
				IPv4NAT:          makeIPv4NATKvp(),
				IPv6NAT:          makeIPv6NATKvp(),
				IPv4Gateway:      net.ParseIP("10.0.0.254"),
				IPv6Gateway:      net.ParseIP("2001::"),
				Ports:            makeEndpointPortsKvp(),
			},
		},
		libapiv3.WorkloadEndpoint{
			ObjectMeta: v1.ObjectMeta{
				Name:   "testnode-k8s-frontend--5gs43-eth0",
				Labels: map[string]string{},
			},
			Spec: libapiv3.WorkloadEndpointSpec{
				Orchestrator:  "k8s",
				Node:          "testnode",
				Pod:           "frontend-5gs43",
				ContainerID:   "133749555694203141592653a",
				Endpoint:      "eth0",
				IPNetworks:    []string{"10.0.0.1/32", "2001::/128"},
				IPNATs:        makeIPNATv3(),
				IPv4Gateway:   "10.0.0.254",
				IPv6Gateway:   "2001::",
				Profiles:      makeProfilesV3(),
				InterfaceName: "cali1234",
				MAC:           "02:42:7d:c6:f0:80",
				Ports:         makeEndpointPortsV3(),
			},
		},
	),
)

var _ = Describe("v1->v3 workload endpoint conversion tests", func() {
	It("Test invalid k8s workloadID (no dot in name) fails to convert", func() {
		w := converters.WorkloadEndpoint{}
		wepBackendV1 := &model.KVPair{
			Key: model.WorkloadEndpointKey{
				Hostname:       "TestNode",
				OrchestratorID: "k8s",
				WorkloadID:     "default/frontend-5gs43",
				EndpointID:     "eth0",
			},
			Value: &model.WorkloadEndpoint{
				Labels:           makeLabelsV1(),
				ActiveInstanceID: "1337495556942031415926535",
				State:            "active",
				Name:             "cali1234",
				Mac:              makeMac(),
				ProfileIDs:       makeProfilesV1(),
				IPv4Nets:         []net.IPNet{net.MustParseNetwork("10.0.0.1/32")},
				IPv6Nets:         []net.IPNet{},
				IPv4NAT:          makeIPv4NATKvp(),
				IPv6NAT:          []model.IPNAT{},
				IPv4Gateway:      net.ParseIP("10.0.0.254"),
				Ports:            makeEndpointPortsKvp(),
			},
		}
		_, err := w.BackendV1ToAPIV3(wepBackendV1)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Equal("malformed k8s workload ID 'default/frontend-5gs43': workload was not added " +
			"through the Calico CNI plugin and cannot be converted"))
	})
})

func makeLabelsV1() map[string]string {
	return map[string]string{
		"calico/k8s_ns": "default",
		"test":          "someValue",
	}
}

// makeLabelsV3 creates some dummy labels to use in tests.
func makeLabelsV3() map[string]string {
	return map[string]string{
		"projectcalico.org/namespace": "default",
		"test":                        "someValue",
	}
}

func makeIPNATv1() []apiv1.IPNAT {
	return []apiv1.IPNAT{
		{
			InternalIP: net.MustParseIP("10.0.0.1"),
			ExternalIP: net.MustParseIP("172.0.0.1"),
		},
		{
			InternalIP: net.MustParseIP("2001::"),
			ExternalIP: net.MustParseIP("2002::"),
		},
	}
}

func makeIPv4NATKvp() []model.IPNAT {
	var ipv4NAT []model.IPNAT
	for _, ipnat := range makeIPNATv1() {
		nat := model.IPNAT{IntIP: ipnat.InternalIP, ExtIP: ipnat.ExternalIP}
		if ipnat.InternalIP.Version() == 4 {
			ipv4NAT = append(ipv4NAT, nat)
		}
	}
	return ipv4NAT
}

func makeIPv6NATKvp() []model.IPNAT {
	var ipv6NAT []model.IPNAT
	for _, ipnat := range makeIPNATv1() {
		nat := model.IPNAT{IntIP: ipnat.InternalIP, ExtIP: ipnat.ExternalIP}
		if ipnat.InternalIP.Version() == 6 {
			ipv6NAT = append(ipv6NAT, nat)
		}
	}
	return ipv6NAT
}

func makeIPNATv3() []libapiv3.IPNAT {
	return []libapiv3.IPNAT{
		{
			InternalIP: "10.0.0.1",
			ExternalIP: "172.0.0.1",
		},
		{
			InternalIP: "2001::",
			ExternalIP: "2002::",
		},
	}
}

func makeProfilesV1() []string {
	return []string{
		"k8s_ns.profile1",
		"profile2",
	}
}

func makeProfilesV3() []string {
	return []string{
		"kns.profile1",
		"profile2",
	}
}

func makeMac() *net.MAC {
	mac, err := cnet.ParseMAC("02:42:7d:c6:f0:80")
	if err != nil {
		panic(err)
	}
	return &net.MAC{mac}
}

func makeEndpointPortsV1() []apiv1.EndpointPort {
	return []apiv1.EndpointPort{
		{
			Name:     "ep1",
			Protocol: numorstring.ProtocolFromString("tcp"),
			Port:     80,
		},
	}
}

func makeEndpointPortsKvp() []model.EndpointPort {
	var ports []model.EndpointPort
	for _, port := range makeEndpointPortsV1() {
		ports = append(ports, model.EndpointPort{
			Name:     port.Name,
			Protocol: port.Protocol,
			Port:     port.Port,
		})
	}
	return ports
}

func makeEndpointPortsV3() []libapiv3.WorkloadEndpointPort {
	return []libapiv3.WorkloadEndpointPort{
		{
			Name:     "ep1",
			Protocol: numorstring.ProtocolFromString("tcp"),
			Port:     80,
		},
	}
}
