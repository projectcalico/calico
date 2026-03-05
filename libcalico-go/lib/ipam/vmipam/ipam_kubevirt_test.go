// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package vmipam

import (
	"context"
	"errors"
	"fmt"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam/ipamtestutils"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func TestVMIPAM(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "VM IPAM Suite")
}

var _ = testutils.E2eDatastoreDescribe("VM IPAM tests", testutils.DatastoreAll, func(config apiconfig.CalicoAPIConfig) {
	var bc bapi.Client
	var ic ipam.Interface
	var kc *kubernetes.Clientset
	var ipPools *ipamtestutils.IPPoolAccessor

	BeforeEach(func() {
		var err error
		config.Spec.K8sClientQPS = 500
		bc, err = backend.NewClient(config)
		Expect(err).NotTo(HaveOccurred())
		ipPools = &ipamtestutils.IPPoolAccessor{Pools: map[string]ipamtestutils.Pool{}}
		ic = ipam.NewIPAMClient(bc, ipPools, &ipamtestutils.FakeReservations{})

		if config.Spec.DatastoreType == "kubernetes" {
			kc = bc.(*k8s.KubeClient).ClientSet
		}
	})

	Context("EnsureActiveVMOwnerAttrs", func() {
		var hostname string
		var handle string
		var allocatedIPs []cnet.IP

		BeforeEach(func() {
			hostname = "test-host-swap"
			handle = "k8s-pod-network.vmi.test-ns.test-vm"

			Expect(bc.Clean()).To(Succeed())
			ipPools.Pools = map[string]ipamtestutils.Pool{}
			ipPools.Pools["10.0.0.0/24"] = ipamtestutils.Pool{Enabled: true}
			ipPools.Pools["fd80:24e2:f998:72d6::/120"] = ipamtestutils.Pool{Enabled: true}
			ipamtestutils.ApplyNode(bc, kc, hostname, nil)

			ctx := context.Background()

			// Allocate dual-stack IPs for the VMI handle
			v4ia, v6ia, err := ic.AutoAssign(ctx, ipam.AutoAssignArgs{
				Num4:        1,
				Num6:        1,
				HandleID:    &handle,
				Hostname:    hostname,
				IntendedUse: v3.IPPoolAllowedUseWorkload,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(v4ia.IPs).To(HaveLen(1))
			Expect(v6ia.IPs).To(HaveLen(1))

			allocatedIPs = []cnet.IP{
				{IP: v4ia.IPs[0].IP},
				{IP: v6ia.IPs[0].IP},
			}

			// Set source pod as active owner and target pod as alternate owner on all IPs
			for _, ip := range allocatedIPs {
				err := ic.SetOwnerAttributes(ctx, ip, handle, &ipam.OwnerAttributeUpdates{
					ActiveOwnerAttrs: map[string]string{
						ipam.AttributePod:       "virt-launcher-source",
						ipam.AttributeNamespace: "test-ns",
					},
					AlternateOwnerAttrs: map[string]string{
						ipam.AttributePod:       "virt-launcher-target",
						ipam.AttributeNamespace: "test-ns",
					},
				}, nil)
				Expect(err).NotTo(HaveOccurred())
			}
		})

		It("should promote target to active owner on all IPs", func() {
			ctx := context.Background()

			err := EnsureActiveVMOwnerAttrs(ctx, ic, "", "test-ns", "test-vm", "virt-launcher-target")
			Expect(err).NotTo(HaveOccurred())

			for _, ip := range allocatedIPs {
				allocAttr, err := ic.GetAssignmentAttributes(ctx, ip)
				Expect(err).NotTo(HaveOccurred())
				Expect(allocAttr.ActiveOwnerAttrs[ipam.AttributePod]).To(Equal("virt-launcher-target"))
				Expect(allocAttr.ActiveOwnerAttrs[ipam.AttributeNamespace]).To(Equal("test-ns"))
				// Source moves to alternate
				Expect(allocAttr.AlternateOwnerAttrs[ipam.AttributePod]).To(Equal("virt-launcher-source"))
				Expect(allocAttr.AlternateOwnerAttrs[ipam.AttributeNamespace]).To(Equal("test-ns"))
			}
		})

		It("should be idempotent - second call succeeds when target is already active", func() {
			ctx := context.Background()

			err := EnsureActiveVMOwnerAttrs(ctx, ic, "", "test-ns", "test-vm", "virt-launcher-target")
			Expect(err).NotTo(HaveOccurred())

			// Call again - should succeed (idempotent)
			err = EnsureActiveVMOwnerAttrs(ctx, ic, "", "test-ns", "test-vm", "virt-launcher-target")
			Expect(err).NotTo(HaveOccurred())

			for _, ip := range allocatedIPs {
				allocAttr, err := ic.GetAssignmentAttributes(ctx, ip)
				Expect(err).NotTo(HaveOccurred())
				Expect(allocAttr.ActiveOwnerAttrs[ipam.AttributePod]).To(Equal("virt-launcher-target"))
			}
		})

		It("should return ErrAlternateOwnerEmpty when alternate is cleared before swap", func() {
			ctx := context.Background()

			// Clear alternate owner on all IPs (simulates target pod deleted before swap)
			for _, ip := range allocatedIPs {
				err := ic.SetOwnerAttributes(ctx, ip, handle, &ipam.OwnerAttributeUpdates{
					ClearAlternateOwner: true,
				}, nil)
				Expect(err).NotTo(HaveOccurred())
			}

			err := EnsureActiveVMOwnerAttrs(ctx, ic, "", "test-ns", "test-vm", "virt-launcher-target")
			Expect(err).To(HaveOccurred())
			Expect(errors.Is(err, ErrAlternateOwnerEmpty)).To(BeTrue(),
				fmt.Sprintf("Expected ErrAlternateOwnerEmpty, got: %v", err))
		})

		It("should return ErrAlternateOwnerMismatch when alternate is a different pod", func() {
			ctx := context.Background()

			// Overwrite alternate with a different pod
			for _, ip := range allocatedIPs {
				err := ic.SetOwnerAttributes(ctx, ip, handle, &ipam.OwnerAttributeUpdates{
					AlternateOwnerAttrs: map[string]string{
						ipam.AttributePod:       "virt-launcher-unexpected",
						ipam.AttributeNamespace: "test-ns",
					},
				}, nil)
				Expect(err).NotTo(HaveOccurred())
			}

			err := EnsureActiveVMOwnerAttrs(ctx, ic, "", "test-ns", "test-vm", "virt-launcher-target")
			Expect(err).To(HaveOccurred())
			Expect(errors.Is(err, ErrAlternateOwnerMismatch)).To(BeTrue(),
				fmt.Sprintf("Expected ErrAlternateOwnerMismatch, got: %v", err))
		})

		It("should fail when no IPs are allocated to the handle", func() {
			ctx := context.Background()

			// Release all IPs
			err := ic.ReleaseByHandle(ctx, handle)
			Expect(err).NotTo(HaveOccurred())

			err = EnsureActiveVMOwnerAttrs(ctx, ic, "", "test-ns", "test-vm", "virt-launcher-target")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("failed to get IPs for handle"))
		})

		It("should succeed when source was already deleted but target is in alternate", func() {
			ctx := context.Background()

			// Clear active owner (simulates source pod deleted and its attrs cleared)
			for _, ip := range allocatedIPs {
				err := ic.SetOwnerAttributes(ctx, ip, handle, &ipam.OwnerAttributeUpdates{
					ClearActiveOwner: true,
				}, nil)
				Expect(err).NotTo(HaveOccurred())
			}

			// Swap should still succeed - it only verifies alternate
			err := EnsureActiveVMOwnerAttrs(ctx, ic, "", "test-ns", "test-vm", "virt-launcher-target")
			Expect(err).NotTo(HaveOccurred())

			for _, ip := range allocatedIPs {
				allocAttr, err := ic.GetAssignmentAttributes(ctx, ip)
				Expect(err).NotTo(HaveOccurred())
				Expect(allocAttr.ActiveOwnerAttrs[ipam.AttributePod]).To(Equal("virt-launcher-target"))
				// Active was empty, so alternate should now be empty (nil map swapped in)
				Expect(allocAttr.AlternateOwnerAttrs).To(BeNil())
			}
		})

		It("should work with custom network name", func() {
			ctx := context.Background()

			// Allocate IPs with a custom network handle
			customHandle := "multus-net1.vmi.test-ns.test-vm"
			v4ia, _, err := ic.AutoAssign(ctx, ipam.AutoAssignArgs{
				Num4:        1,
				HandleID:    &customHandle,
				Hostname:    hostname,
				IntendedUse: v3.IPPoolAllowedUseWorkload,
			})
			Expect(err).NotTo(HaveOccurred())
			customIP := cnet.IP{IP: v4ia.IPs[0].IP}

			// Set owners
			err = ic.SetOwnerAttributes(ctx, customIP, customHandle, &ipam.OwnerAttributeUpdates{
				ActiveOwnerAttrs: map[string]string{
					ipam.AttributePod:       "virt-launcher-source",
					ipam.AttributeNamespace: "test-ns",
				},
				AlternateOwnerAttrs: map[string]string{
					ipam.AttributePod:       "virt-launcher-target",
					ipam.AttributeNamespace: "test-ns",
				},
			}, nil)
			Expect(err).NotTo(HaveOccurred())

			err = EnsureActiveVMOwnerAttrs(ctx, ic, "multus-net1", "test-ns", "test-vm", "virt-launcher-target")
			Expect(err).NotTo(HaveOccurred())

			allocAttr, err := ic.GetAssignmentAttributes(ctx, customIP)
			Expect(err).NotTo(HaveOccurred())
			Expect(allocAttr.ActiveOwnerAttrs[ipam.AttributePod]).To(Equal("virt-launcher-target"))
		})

		It("should handle partial success - already-swapped IPs are skipped on retry", func() {
			ctx := context.Background()

			// Manually swap only the first IP
			firstIP := allocatedIPs[0]
			err := ic.SetOwnerAttributes(ctx, firstIP, handle, &ipam.OwnerAttributeUpdates{
				ActiveOwnerAttrs: map[string]string{
					ipam.AttributePod:       "virt-launcher-target",
					ipam.AttributeNamespace: "test-ns",
				},
				AlternateOwnerAttrs: map[string]string{
					ipam.AttributePod:       "virt-launcher-source",
					ipam.AttributeNamespace: "test-ns",
				},
			}, nil)
			Expect(err).NotTo(HaveOccurred())

			// Now call the function - first IP should be skipped, second IP should be swapped
			err = EnsureActiveVMOwnerAttrs(ctx, ic, "", "test-ns", "test-vm", "virt-launcher-target")
			Expect(err).NotTo(HaveOccurred())

			// Both IPs should now have target as active
			for _, ip := range allocatedIPs {
				allocAttr, err := ic.GetAssignmentAttributes(ctx, ip)
				Expect(err).NotTo(HaveOccurred())
				Expect(allocAttr.ActiveOwnerAttrs[ipam.AttributePod]).To(Equal("virt-launcher-target"))
			}
		})
	})
})
