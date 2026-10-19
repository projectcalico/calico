// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package utils_test

import (
	"testing"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/utils"
)

func TestParsePodHandleID(t *testing.T) {
	const netName = "k8s-pod-network"

	for _, tc := range []struct {
		name        string
		handle      string
		expect      bool
		containerID string
	}{
		{
			name:        "earlier sandbox of the same pod",
			handle:      "k8s-pod-network.old-container",
			expect:      true,
			containerID: "old-container",
		},
		{
			// kubelet retrying ADD after a partial failure. The address is
			// already ours.
			name:        "this same sandbox",
			handle:      "k8s-pod-network.new-container",
			expect:      true,
			containerID: "new-container",
		},
		{
			name:        "trailing carriage return from the host-local migration",
			handle:      "k8s-pod-network.old-container\r",
			expect:      true,
			containerID: "old-container",
		},
		{
			name:   "different network",
			handle: "other-network.old-container",
			expect: false,
		},
		{
			// Enterprise appends the interface name. Such a handle never reaches
			// this parser, and a container ID cannot contain a dot.
			name:   "handle carrying an interface component",
			handle: "k8s-pod-network.old-container.eth0",
			expect: false,
		},
		{
			name:   "pre-v3 workload handle",
			handle: "k8s-pod-network.default.mypod",
			expect: false,
		},
		{
			name:   "VM-scoped handle",
			handle: "k8s-pod-network.vmi.default.vm1",
			expect: false,
		},
		{
			name:   "tunnel address handle",
			handle: "ipip-tunnel-addr-node1",
			expect: false,
		},
		{
			name:   "load balancer handle",
			handle: "lb-abc123",
			expect: false,
		},
		{
			name:   "windows reserved handle",
			handle: "windows-reserved-ipam-handle",
			expect: false,
		},
		{
			name:   "empty handle",
			handle: "",
			expect: false,
		},
		{
			name:   "network name only",
			handle: "k8s-pod-network.",
			expect: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed, ok := utils.ParsePodHandleID(tc.handle, netName)
			if ok != tc.expect {
				t.Fatalf("ParsePodHandleID(%q) ok = %v, want %v", tc.handle, ok, tc.expect)
			}
			if ok && parsed.ContainerID != tc.containerID {
				t.Errorf("ParsePodHandleID(%q) container ID = %q, want %q", tc.handle, parsed.ContainerID, tc.containerID)
			}
		})
	}
}

func TestParsePodHandleIDRoundTrip(t *testing.T) {
	const (
		netName     = "k8s-pod-network"
		containerID = "abc123"
	)

	parsed, ok := utils.ParsePodHandleID(utils.GetHandleID(netName, containerID, "ns.pod"), netName)
	if !ok {
		t.Fatal("a handle this package generated should parse")
	}
	if parsed.ContainerID != containerID {
		t.Errorf("container ID = %q, want %q", parsed.ContainerID, containerID)
	}
	if parsed.Network != netName {
		t.Errorf("network = %q, want %q", parsed.Network, netName)
	}
}
