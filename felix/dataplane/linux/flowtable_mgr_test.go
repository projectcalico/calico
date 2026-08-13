// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package intdataplane

import (
	"regexp"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	dpsets "github.com/projectcalico/calico/felix/dataplane/ipsets"
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
)

type recordingHandler struct {
	lastOverlay  []string
	lastExternal []string
}

func (h *recordingHandler) SetWorkloadInterfaces(ifces []string) {}

func (h *recordingHandler) SetOverlayDevices(devices []string) {
	h.lastOverlay = append([]string(nil), devices...)
}

func (h *recordingHandler) SetExternalDevices(ifces []string) {
	h.lastExternal = append([]string(nil), ifces...)
}

var _ = Describe("flowtableManager", func() {
	It("tracks external interfaces matching the pattern and ignores others", func() {
		h := &recordingHandler{}
		m := newFlowtableManager([]flowtableTarget{{handler: h}}, regexp.MustCompile("^eth"))

		m.OnUpdate(&ifaceStateUpdate{Name: "eth0", State: ifacemonitor.StateUp})
		m.OnUpdate(&ifaceStateUpdate{Name: "cali123", State: ifacemonitor.StateUp})
		Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
		Expect(h.lastExternal).To(ConsistOf("eth0"))

		m.OnUpdate(&ifaceStateUpdate{Name: "eth0", State: ifacemonitor.StateDown})
		Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
		Expect(h.lastExternal).To(BeEmpty())
	})

	It("only offloads overlay devices once they exist", func() {
		h := &recordingHandler{}
		m := newFlowtableManager([]flowtableTarget{{handler: h, overlayDevices: []string{"vxlan.calico", "tunl0"}}}, nil)

		// Before any device comes up the overlay set is empty, so the flowtable references nothing
		// the kernel lacks.
		Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
		Expect(h.lastOverlay).To(BeEmpty())

		m.OnUpdate(&ifaceStateUpdate{Name: "vxlan.calico", State: ifacemonitor.StateUp})
		Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
		Expect(h.lastOverlay).To(ConsistOf("vxlan.calico"))

		m.OnUpdate(&ifaceStateUpdate{Name: "vxlan.calico", State: ifacemonitor.StateDown})
		Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
		Expect(h.lastOverlay).To(BeEmpty())
	})

	It("routes each overlay device only to the handler that owns it", func() {
		v4 := &recordingHandler{}
		v6 := &recordingHandler{}
		m := newFlowtableManager([]flowtableTarget{
			{handler: v4, overlayDevices: []string{"vxlan.calico"}},
			{handler: v6, overlayDevices: []string{"vxlan-v6.calico"}},
		}, regexp.MustCompile("^eth"))

		m.OnUpdate(&ifaceStateUpdate{Name: "vxlan.calico", State: ifacemonitor.StateUp})
		m.OnUpdate(&ifaceStateUpdate{Name: "vxlan-v6.calico", State: ifacemonitor.StateUp})
		m.OnUpdate(&ifaceStateUpdate{Name: "eth0", State: ifacemonitor.StateUp})
		Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())

		Expect(v4.lastOverlay).To(ConsistOf("vxlan.calico"))
		Expect(v6.lastOverlay).To(ConsistOf("vxlan-v6.calico"))

		// External devices are shared across handlers.
		Expect(v4.lastExternal).To(ConsistOf("eth0"))
		Expect(v6.lastExternal).To(ConsistOf("eth0"))
	})
})

var _ = Describe("flowtableExclusionManager", func() {
	var (
		m      *flowtableExclusionManager
		ipSets *dpsets.MockIPSets
	)

	wepID := &proto.WorkloadEndpointID{OrchestratorId: "k8s", WorkloadId: "wl1", EndpointId: "ep1"}

	BeforeEach(func() {
		ipSets = dpsets.NewMockIPSets()
		m = newFlowtableExclusionManager(ipSets, 4, 1024)
	})

	members := func() []string {
		s := ipSets.Members[rules.IPSetIDNoFlowOffload]
		Expect(s).NotTo(BeNil())
		return s.Slice()
	}

	It("programs an empty set at start of day", func() {
		Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
		Expect(members()).To(BeEmpty())
	})

	DescribeTable("excludes endpoints whose features need the forward hooks",
		func(wep *proto.WorkloadEndpoint, expected []string) {
			wep.Ipv4Nets = []string{"10.65.0.2/32"}
			wep.Ipv6Nets = []string{"dead:beef::2/128"}
			m.OnUpdate(&proto.WorkloadEndpointUpdate{Id: wepID, Endpoint: wep})
			Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
			Expect(members()).To(ConsistOf(expected))
		},
		Entry("DSCP marking",
			&proto.WorkloadEndpoint{QosPolicies: []*proto.QoSPolicy{{Dscp: 20}}},
			[]string{"10.65.0.2"}),
		Entry("ingress connection limit",
			&proto.WorkloadEndpoint{QosControls: &proto.QoSControls{IngressMaxConnections: 10}},
			[]string{"10.65.0.2"}),
		Entry("egress connection limit",
			&proto.WorkloadEndpoint{QosControls: &proto.QoSControls{EgressMaxConnections: 10}},
			[]string{"10.65.0.2"}),
		Entry("ingress packet rate limit",
			&proto.WorkloadEndpoint{QosControls: &proto.QoSControls{IngressPacketRate: 1000}},
			[]string{"10.65.0.2"}),
		Entry("egress packet rate limit",
			&proto.WorkloadEndpoint{QosControls: &proto.QoSControls{EgressPacketRate: 1000}},
			[]string{"10.65.0.2"}),
		Entry("bandwidth QoS, which the fast path still honours",
			&proto.WorkloadEndpoint{QosControls: &proto.QoSControls{IngressBandwidth: 1000}},
			[]string{}),
		Entry("no QoS at all", &proto.WorkloadEndpoint{}, []string{}),
	)

	It("drops an endpoint from the set when its QoS controls are cleared", func() {
		m.OnUpdate(&proto.WorkloadEndpointUpdate{Id: wepID, Endpoint: &proto.WorkloadEndpoint{
			Ipv4Nets:    []string{"10.65.0.2/32"},
			QosControls: &proto.QoSControls{IngressMaxConnections: 10},
		}})
		Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
		Expect(members()).To(ConsistOf("10.65.0.2"))

		m.OnUpdate(&proto.WorkloadEndpointUpdate{Id: wepID, Endpoint: &proto.WorkloadEndpoint{
			Ipv4Nets: []string{"10.65.0.2/32"},
		}})
		Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
		Expect(members()).To(BeEmpty())
	})

	It("drops an endpoint from the set when it is removed", func() {
		m.OnUpdate(&proto.WorkloadEndpointUpdate{Id: wepID, Endpoint: &proto.WorkloadEndpoint{
			Ipv4Nets:    []string{"10.65.0.2/32"},
			QosPolicies: []*proto.QoSPolicy{{Dscp: 20}},
		}})
		Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
		Expect(members()).To(ConsistOf("10.65.0.2"))

		m.OnUpdate(&proto.WorkloadEndpointRemove{Id: wepID})
		Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
		Expect(members()).To(BeEmpty())
	})

	It("excludes host endpoints with DSCP policies", func() {
		hepID := &proto.HostEndpointID{EndpointId: "hep1"}
		m.OnUpdate(&proto.HostEndpointUpdate{Id: hepID, Endpoint: &proto.HostEndpoint{
			ExpectedIpv4Addrs: []string{"192.168.0.1"},
			QosPolicies:       []*proto.QoSPolicy{{Dscp: 20}},
		}})
		Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
		Expect(members()).To(ConsistOf("192.168.0.1"))

		m.OnUpdate(&proto.HostEndpointRemove{Id: hepID})
		Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
		Expect(members()).To(BeEmpty())
	})

	It("tracks the IPs of the configured family only", func() {
		v6 := newFlowtableExclusionManager(ipSets, 6, 1024)
		v6.OnUpdate(&proto.WorkloadEndpointUpdate{Id: wepID, Endpoint: &proto.WorkloadEndpoint{
			Ipv4Nets:    []string{"10.65.0.2/32"},
			Ipv6Nets:    []string{"dead:beef::2/128"},
			QosPolicies: []*proto.QoSPolicy{{Dscp: 20}},
		}})
		Expect(v6.CompleteDeferredWork()).NotTo(HaveOccurred())
		Expect(members()).To(ConsistOf("dead:beef::2"))
	})
})
