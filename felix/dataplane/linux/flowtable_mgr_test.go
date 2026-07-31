// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package intdataplane

import (
	"regexp"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/ifacemonitor"
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
