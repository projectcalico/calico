// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package intdataplane

import (
	"regexp"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/nftables"
)

type recordingHandler struct {
	lastExternal []string
}

func (h *recordingHandler) SetWorkloadInterfaces(ifces []string) {}

func (h *recordingHandler) SetExternalDevices(ifces []string) {
	h.lastExternal = append([]string(nil), ifces...)
}

var _ = Describe("flowtableManager", func() {
	It("tracks interfaces matching the pattern and ignores others", func() {
		h := &recordingHandler{}
		m := newFlowtableManager([]nftables.FlowTableHandler{h}, regexp.MustCompile("^eth"))

		m.OnUpdate(&ifaceStateUpdate{Name: "eth0", State: ifacemonitor.StateUp})
		m.OnUpdate(&ifaceStateUpdate{Name: "cali123", State: ifacemonitor.StateUp})
		Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
		Expect(h.lastExternal).To(ConsistOf("eth0"))

		m.OnUpdate(&ifaceStateUpdate{Name: "eth0", State: ifacemonitor.StateDown})
		Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
		Expect(h.lastExternal).To(BeEmpty())
	})
})
