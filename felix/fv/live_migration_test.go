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

package fv_test

import (
	"context"
	"regexp"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	kubevirtv1 "kubevirt.io/api/core/v1"
	kubevirtclient "kubevirt.io/client-go/kubevirt/typed/core/v1"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam/vmipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

// This file covers Felix's route programming for VM live migration, in two suites:
//
//   - An OpenStack-style suite (etcd datastore), driven by creating WorkloadEndpoint and
//     LiveMigration resources directly, as networking-calico does.
//   - A KubeVirt-style suite (Kubernetes datastore), driven by creating Pods and KubeVirt
//     VirtualMachineInstanceMigration (VMIM) resources, which the Kubernetes backend converts to
//     LiveMigrations.
//
// In both suites the migrating VM is modelled by two FV workloads with the same IP, one on each
// of two Felix hosts.  The expected route programming on the target host, as the migration
// progresses, is:
//
//  1. No route at all, from when the target WEP and LiveMigration exist until the target
//     workload becomes live (Felix FSM states Base and Target).
//  2. A route with elevated priority (lower metric), from when Felix detects the target's GARP,
//     or from when the migration completes if the GARP is missed (states Live and TimeWait).
//  3. Reversion to normal priority once the migration has completed and
//     LiveMigrationRouteConvergenceTime has elapsed (back to state Base).
//
// Throughout, the source host's route programming for its WEP is normal.
const (
	// Both workloads model the same migrating VM, so they share this IP.
	lmMigratingIP = "10.65.0.2"

	// Route priorities for these tests, matching the IPv4ElevatedRoutePriority and
	// IPv4NormalRoutePriority defaults; lmTopologyOptions pins them explicitly so that the
	// metric assertions cannot be broken by a change to the defaults.  Note that lower
	// metric = more preferred.
	lmElevatedPriority = "512"
	lmNormalPriority   = "1024"

	// Corresponding metric strings expected in "ip route show" output.
	lmElevatedMetric = "metric " + lmElevatedPriority
	lmNormalMetric   = "metric " + lmNormalPriority

	// LiveMigrationRouteConvergenceTime for these tests, in seconds.  Long enough that a
	// Consistently over a few seconds fits within it, short enough that waiting for reversion
	// to normal priority doesn't slow the tests down too much.
	lmConvergenceTimeSecs = "8"
)

// lmTopologyOptions returns the topology options shared by both live migration suites: flat
// (unencapsulated) IPv4 routing, as in the OpenStack use case.  With no encap and the default
// RouteSource, Felix programs only local workload routes, which are the subject of these tests.
func lmTopologyOptions() infrastructure.TopologyOptions {
	opts := infrastructure.DefaultTopologyOptions()
	opts.IPIPMode = api.IPIPModeNever
	opts.EnableIPv6 = false
	opts.ExtraEnvVars["FELIX_LIVEMIGRATIONROUTECONVERGENCETIME"] = lmConvergenceTimeSecs
	opts.ExtraEnvVars["FELIX_IPV4ELEVATEDROUTEPRIORITY"] = lmElevatedPriority
	opts.ExtraEnvVars["FELIX_IPV4NORMALROUTEPRIORITY"] = lmNormalPriority

	// The tests' routing expectations assume IPAM-derived routing (the default RouteSource);
	// make that explicit too.
	opts.ExtraEnvVars["FELIX_ROUTESOURCE"] = "CalicoIPAM"
	opts.FelixDebugFilenameRegex = "live_migration"
	return opts
}

// lmWorkloadRoute returns a function that fetches the host's main-table route for the given
// workload's IP on that workload's interface, or "" if there is no such route.
func lmWorkloadRoute(felix *infrastructure.Felix, w *workload.Workload) func() string {
	return func() string {
		out, err := felix.ExecOutput("ip", "route", "show", "dev", w.InterfaceName)
		if err != nil {
			// Interface not present (e.g. workload stopped); no route.
			return ""
		}
		for _, line := range strings.Split(out, "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 && fields[0] == w.IP {
				return strings.TrimSpace(line)
			}
		}
		return ""
	}
}

// lmSendGARP sends a gratuitous ARP for the workload's own IP from inside its network namespace,
// as QEMU does when a migrated VM resumes on the target host.  It egresses over the veth and is
// seen by Felix's GARP listener on the host-side interface.
func lmSendGARP(w *workload.Workload) {
	out, err := w.RunCmd("arping", "-U", "-c", "1", "-I", "eth0", w.IP)
	if err != nil {
		log.WithError(err).WithField("output", out).Info("arping returned an error")
	}
}

// lmGARPElicitsRoute sends GARPs from the workload until the expected route appears on the host.
// Retrying the GARP makes the test robust against the GARP being sent just before Felix's
// listener is ready.
func lmGARPElicitsRoute(felix *infrastructure.Felix, w *workload.Workload, expectedMetric string) {
	route := lmWorkloadRoute(felix, w)
	EventuallyWithOffset(1, func() string {
		lmSendGARP(w)
		return route()
	}, "10s", "500ms").Should(ContainSubstring(expectedMetric))
}

// lmWatchForState returns a channel that is closed when the given Felix logs a live migration
// FSM transition to the given state.
func lmWatchForState(felix *infrastructure.Felix, toState string) chan struct{} {
	return felix.WatchStdoutFor(regexp.MustCompile(
		"Live migration state transition.*to=" + toState))
}

func lmExpectReachableVia(felix *infrastructure.Felix, w *workload.Workload) {
	cc := &connectivity.Checker{}
	cc.ExpectSome(felix, w)
	cc.CheckConnectivity()
}

func lmExpectNotReachableVia(felix *infrastructure.Felix, w *workload.Workload) {
	cc := &connectivity.Checker{}
	cc.ExpectNone(felix, w)
	cc.CheckConnectivity()
}

// lmDumpDiagsOnFailure logs each Felix's routing table and interfaces if the current test failed.
func lmDumpDiagsOnFailure(tc infrastructure.TopologyContainers) {
	if !CurrentGinkgoTestDescription().Failed {
		return
	}
	for _, felix := range tc.Felixes {
		felix.Exec("ip", "route", "show")
		felix.Exec("ip", "addr", "show")
	}
}

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ live migration route programming; with 2 nodes",
	[]apiconfig.DatastoreType{apiconfig.EtcdV3},
	func(getInfra infrastructure.InfraFactory) {
		var (
			infra          infrastructure.DatastoreInfra
			tc             infrastructure.TopologyContainers
			calicoClient   client.Interface
			source, target *workload.Workload
		)

		BeforeEach(func() {
			infra = getInfra()

			tc, calicoClient = infrastructure.StartNNodeTopology(2, lmTopologyOptions(), infra)
			infra.AddDefaultAllow()

			// The migrating "VM": one workload on each host, with the same IP.  The
			// source starts with a WorkloadEndpoint; the target's WEP is created by
			// each test at the point in the migration flow where the orchestrator
			// would create it.  The WEPs carry the "openstack" orchestrator ID, as
			// networking-calico's would, so that any OpenStack-specific handling in
			// Felix is exercised.
			source = workload.Run(tc.Felixes[0], "source", "default", lmMigratingIP, "8055", "tcp")
			source.WorkloadEndpoint.Spec.Orchestrator = api.OrchestratorOpenStack
			source.ConfigureInInfra(infra)
			target = workload.Run(tc.Felixes[1], "target", "default", lmMigratingIP, "8055", "tcp")
			target.WorkloadEndpoint.Spec.Orchestrator = api.OrchestratorOpenStack
		})

		AfterEach(func() {
			lmDumpDiagsOnFailure(tc)

			// Topology/workload cleanup is handled by infra.Stop() via
			// DatastoreDescribe.
		})

		// wepID builds the LiveMigration identifier for an FV workload's WEP.  These fields
		// must match the components of Felix's v1 WorkloadEndpointKey for the WEP, i.e. what
		// names.ConvertWorkloadEndpointV3KeyToV1Key produces.
		wepID := func(w *workload.Workload) *internalapi.WorkloadEndpointIdentifier {
			wep := w.WorkloadEndpoint
			namespace := wep.Namespace
			if namespace == "" {
				namespace = "default"
			}
			return &internalapi.WorkloadEndpointIdentifier{
				Hostname:       wep.Spec.Node,
				OrchestratorID: wep.Spec.Orchestrator,
				WorkloadID:     namespace + "/" + wep.Spec.Workload,
				EndpointID:     wep.Spec.Endpoint,
			}
		}

		// createLiveMigration creates a LiveMigration resource in the same way as
		// networking-calico does for OpenStack, identifying the source and target WEPs
		// directly by their identifier fields.
		createLiveMigration := func(name string, src, tgt *workload.Workload) {
			lm := internalapi.NewLiveMigration()
			lm.Name = name
			lm.Namespace = "default"
			lm.Spec.Source = &internalapi.LiveMigrationSource{WorkloadEndpoint: wepID(src)}
			lm.Spec.Target = &internalapi.LiveMigrationTarget{WorkloadEndpoint: wepID(tgt)}
			_, err := calicoClient.LiveMigrations().Create(context.Background(), lm, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
		}

		deleteLiveMigration := func(name string) {
			_, err := calicoClient.LiveMigrations().Delete(context.Background(), "default", name, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
		}

		It("should follow the mainline migration flow, with GARP detection", func() {
			srcRouteFn := lmWorkloadRoute(tc.Felixes[0], source)
			tgtRouteFn := lmWorkloadRoute(tc.Felixes[1], target)

			By("programming a normal-priority route for the source workload")
			Eventually(srcRouteFn, "10s", "200ms").Should(ContainSubstring(lmNormalMetric))
			lmExpectReachableVia(tc.Felixes[0], source)

			By("creating the LiveMigration and then the target WEP")
			targetSeen := lmWatchForState(tc.Felixes[1], "Target")
			createLiveMigration("migration-1", source, target)
			target.ConfigureInInfra(infra)

			By("suppressing the target workload's route while awaiting the GARP")
			Eventually(targetSeen, "10s").Should(BeClosed())
			Consistently(tgtRouteFn, "3s", "500ms").Should(BeEmpty(),
				"target route should be suppressed before the target VM is live")
			Expect(srcRouteFn()).To(ContainSubstring(lmNormalMetric),
				"source route should be untouched during migration")
			lmExpectReachableVia(tc.Felixes[0], source)
			lmExpectNotReachableVia(tc.Felixes[1], target)

			By("programming an elevated-priority route when the target sends a GARP")
			lmGARPElicitsRoute(tc.Felixes[1], target, lmElevatedMetric)
			lmExpectReachableVia(tc.Felixes[1], target)

			By("completing the migration: removing the source WEP and the LiveMigration")
			source.RemoveFromInfra(infra)
			deleteLiveMigration("migration-1")

			By("keeping the elevated route until the convergence time has elapsed")
			Consistently(tgtRouteFn, "3s", "500ms").Should(ContainSubstring(lmElevatedMetric))
			Eventually(srcRouteFn, "10s", "200ms").Should(BeEmpty(),
				"source route should be removed with the source WEP")
			Eventually(tgtRouteFn, "15s", "500ms").Should(ContainSubstring(lmNormalMetric))
			lmExpectReachableVia(tc.Felixes[1], target)
		})

		It("should complete a migration even if the GARP is missed", func() {
			tgtRouteFn := lmWorkloadRoute(tc.Felixes[1], target)

			By("creating the LiveMigration and then the target WEP")
			targetSeen := lmWatchForState(tc.Felixes[1], "Target")
			createLiveMigration("migration-1", source, target)
			target.ConfigureInInfra(infra)
			Eventually(targetSeen, "10s").Should(BeClosed())
			Consistently(tgtRouteFn, "3s", "500ms").Should(BeEmpty())

			By("completing the migration without any GARP having been sent")
			source.RemoveFromInfra(infra)
			deleteLiveMigration("migration-1")

			By("programming an elevated route and then reverting to normal priority")
			Eventually(tgtRouteFn, "10s", "200ms").Should(ContainSubstring(lmElevatedMetric))
			lmExpectReachableVia(tc.Felixes[1], target)
			Eventually(tgtRouteFn, "15s", "500ms").Should(ContainSubstring(lmNormalMetric))
			lmExpectReachableVia(tc.Felixes[1], target)
		})

		It("should handle migration failure", func() {
			srcRouteFn := lmWorkloadRoute(tc.Felixes[0], source)
			tgtRouteFn := lmWorkloadRoute(tc.Felixes[1], target)

			By("creating the LiveMigration and then the target WEP")
			targetSeen := lmWatchForState(tc.Felixes[1], "Target")
			createLiveMigration("migration-1", source, target)
			target.ConfigureInInfra(infra)
			Eventually(targetSeen, "10s").Should(BeClosed())
			Consistently(tgtRouteFn, "3s", "500ms").Should(BeEmpty())

			By("cleaning up the failed migration: removing the target WEP and LiveMigration")
			baseSeen := lmWatchForState(tc.Felixes[1], "Base")
			target.RemoveFromInfra(infra)
			deleteLiveMigration("migration-1")
			Eventually(baseSeen, "10s").Should(BeClosed())

			By("never programming a route for the failed target")
			Consistently(tgtRouteFn, "3s", "500ms").Should(BeEmpty())

			By("leaving the source untouched throughout")
			Expect(srcRouteFn()).To(ContainSubstring(lmNormalMetric))
			lmExpectReachableVia(tc.Felixes[0], source)
		})

		It("should handle immediate re-migration back to the original host", func() {
			srcRouteFn := lmWorkloadRoute(tc.Felixes[0], source)
			tgtRouteFn := lmWorkloadRoute(tc.Felixes[1], target)

			By("migrating to the target host")
			createLiveMigration("migration-1", source, target)
			target.ConfigureInInfra(infra)
			lmGARPElicitsRoute(tc.Felixes[1], target, lmElevatedMetric)

			By("starting a re-migration back to the original host")
			// The workloads swap roles: the target of the first migration becomes the
			// source of the second, and vice versa.  While both LiveMigrations exist,
			// both WEPs count as targets (target role takes priority over source), so
			// the original workload's route is suppressed but the first migration's
			// target keeps its elevated route.
			createLiveMigration("migration-2", target, source)
			Eventually(srcRouteFn, "10s", "200ms").Should(BeEmpty(),
				"original workload's route should be suppressed as re-migration target")
			Expect(tgtRouteFn()).To(ContainSubstring(lmElevatedMetric))

			By("reverting the re-migration's source to a normal route immediately")
			// Once the first LiveMigration is deleted, the first migration's target
			// becomes purely a migration source, which takes effect immediately, with
			// no elevated-priority TimeWait period.
			deleteLiveMigration("migration-1")
			Eventually(tgtRouteFn, "10s", "200ms").Should(ContainSubstring(lmNormalMetric))

			By("completing the reverse migration with a GARP from the original workload")
			lmGARPElicitsRoute(tc.Felixes[0], source, lmElevatedMetric)
			lmExpectReachableVia(tc.Felixes[0], source)

			By("finishing: removing the reverse migration's source WEP and LiveMigration")
			target.RemoveFromInfra(infra)
			deleteLiveMigration("migration-2")
			Consistently(srcRouteFn, "3s", "500ms").Should(ContainSubstring(lmElevatedMetric))
			Eventually(tgtRouteFn, "10s", "200ms").Should(BeEmpty())
			Eventually(srcRouteFn, "15s", "500ms").Should(ContainSubstring(lmNormalMetric))
			lmExpectReachableVia(tc.Felixes[0], source)
		})

		It("should withdraw the target's route if the WEP is created before the LiveMigration", func() {
			tgtRouteFn := lmWorkloadRoute(tc.Felixes[1], target)

			By("programming a normal route when the target WEP is created with no LiveMigration")
			target.ConfigureInInfra(infra)
			Eventually(tgtRouteFn, "10s", "200ms").Should(ContainSubstring(lmNormalMetric))

			By("withdrawing the route when the LiveMigration arrives")
			createLiveMigration("migration-1", source, target)
			Eventually(tgtRouteFn, "10s", "200ms").Should(BeEmpty())
			Consistently(tgtRouteFn, "3s", "500ms").Should(BeEmpty())
		})
	})

// The KubeVirt-style suite.  In the Kubernetes datastore there is no stored LiveMigration
// resource; instead the Kubernetes backend derives LiveMigrations from KubeVirt
// VirtualMachineInstanceMigration (VMIM) resources: the source is identified by
// Status.MigrationState.SourcePod, and the target by a selector over the VMI-name and
// migration-job labels that KubeVirt puts on the target virt-launcher pod.  These tests create
// Pods (via the FV workload machinery) and VMIMs accordingly.
//
// Note that FV tests create Pods with their IPs directly in Pod.Status.PodIPs; the CNI plugin is
// not involved.  The IPAM state that the CNI plugin would normally create for a KubeVirt VM is
// seeded directly via the IPAM client, which also lets us verify Felix's owner-attribute swap on
// migration.
var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ live migration route programming (KubeVirt); with 2 nodes",
	[]apiconfig.DatastoreType{apiconfig.Kubernetes},
	func(getInfra infrastructure.InfraFactory) {
		const vmiName = "vmi-1"

		var (
			infra          infrastructure.DatastoreInfra
			tc             infrastructure.TopologyContainers
			calicoClient   client.Interface
			vmimClient     kubevirtclient.VirtualMachineInstanceMigrationInterface
			source, target *workload.Workload
		)

		BeforeEach(func() {
			infra = getInfra()
			kds := infra.(*infrastructure.K8sDatastoreInfra)

			// The VMIM CRD must be served before Felix starts: Felix's syncer treats
			// a missing backing API as a valid long-term state and retries only every
			// 30 minutes.
			restConfig := &rest.Config{
				Host:            kds.Endpoint,
				TLSClientConfig: rest.TLSClientConfig{Insecure: true},
				QPS:             100,
				Burst:           100,
			}
			lmEnsureVMIMCRD(restConfig)
			kvClient, err := kubevirtclient.NewForConfig(restConfig)
			Expect(err).NotTo(HaveOccurred())
			vmimClient = kvClient.VirtualMachineInstanceMigrations("default")

			tc, calicoClient = infrastructure.StartNNodeTopology(2, lmTopologyOptions(), infra)
			infra.AddDefaultAllow()

			// The migrating "VM": one pod on each node, with the same IP.  The
			// source starts out registered; the target pod is created by each test at
			// the point in the migration flow where KubeVirt would create the target
			// virt-launcher pod.
			source = workload.Run(tc.Felixes[0], "source", "default", lmMigratingIP, "8055", "tcp")
			source.ConfigureInInfra(infra)
			target = workload.Run(tc.Felixes[1], "target", "default", lmMigratingIP, "8055", "tcp")
		})

		AfterEach(func() {
			lmDumpDiagsOnFailure(tc)

			// Clean up resources that the FV infra's own cleanup doesn't know about:
			// VMIMs and the seeded IPAM allocation.  The nil checks guard against
			// BeforeEach having failed before these clients were set up.
			if vmimClient != nil {
				_ = vmimClient.DeleteCollection(context.Background(), metav1.DeleteOptions{}, metav1.ListOptions{})
			}
			if calicoClient != nil {
				handleID := vmipam.CreateVMHandleID("", "default", vmiName)
				_ = calicoClient.IPAM().ReleaseByHandle(context.Background(), handleID)
			}
		})

		// createVMIM creates a VMIM for the migrating VMI, in the given phase, and returns
		// the created object (whose UID the target pod's migration-job label must match).
		// KubeVirt populates Status.MigrationState.SourcePod once the migration is underway;
		// pass sourcePod="" to model the earlier phases.
		createVMIM := func(name string, phase kubevirtv1.VirtualMachineInstanceMigrationPhase, sourcePod string) *kubevirtv1.VirtualMachineInstanceMigration {
			vmim := &kubevirtv1.VirtualMachineInstanceMigration{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
				Spec:       kubevirtv1.VirtualMachineInstanceMigrationSpec{VMIName: vmiName},
				Status:     kubevirtv1.VirtualMachineInstanceMigrationStatus{Phase: phase},
			}
			if sourcePod != "" {
				vmim.Status.MigrationState = &kubevirtv1.VirtualMachineInstanceMigrationState{
					SourcePod: sourcePod,
				}
			}
			created, err := vmimClient.Create(context.Background(), vmim, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			return created
		}

		setVMIMPhase := func(name string, phase kubevirtv1.VirtualMachineInstanceMigrationPhase) {
			vmim, err := vmimClient.Get(context.Background(), name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			vmim.Status.Phase = phase
			_, err = vmimClient.Update(context.Background(), vmim, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())
		}

		// configureTargetPod registers the target pod, labelled as KubeVirt labels the
		// target virt-launcher pod: with the VMI name and the migration job's UID.
		configureTargetPod := func(vmim *kubevirtv1.VirtualMachineInstanceMigration) {
			target.WorkloadEndpoint.Labels[kubevirtv1.VirtualMachineInstanceIDLabel] = vmiName
			target.WorkloadEndpoint.Labels[kubevirtv1.MigrationJobLabel] = string(vmim.UID)
			target.ConfigureInInfra(infra)
		}

		// seedVMIPAM creates the IPAM allocation that the CNI plugin would have created for
		// the VM: the shared IP allocated under the VMI's handle, with the source pod as the
		// active owner and the target pod as the alternate owner.
		seedVMIPAM := func() (cnet.IP, string) {
			ctx := context.Background()
			ip := cnet.MustParseIP(lmMigratingIP)
			handleID := vmipam.CreateVMHandleID("", "default", vmiName)
			err := calicoClient.IPAM().AssignIP(ctx, ipam.AssignIPArgs{
				IP:       ip,
				HandleID: &handleID,
				Attrs: map[string]string{
					ipam.AttributeNamespace: "default",
					ipam.AttributePod:       source.Name,
				},
				Hostname: tc.Felixes[0].Hostname,
			})
			Expect(err).NotTo(HaveOccurred())
			err = calicoClient.IPAM().SetOwnerAttributes(ctx, ip, handleID,
				&ipam.OwnerAttributeUpdates{
					ActiveOwnerAttrs: map[string]string{
						ipam.AttributeNamespace: "default",
						ipam.AttributePod:       source.Name,
					},
					AlternateOwnerAttrs: map[string]string{
						ipam.AttributeNamespace: "default",
						ipam.AttributePod:       target.Name,
					},
				}, nil)
			Expect(err).NotTo(HaveOccurred())
			return ip, handleID
		}

		activeOwnerPod := func(ip cnet.IP) func() string {
			return func() string {
				attrs, err := calicoClient.IPAM().GetAssignmentAttributes(context.Background(), ip)
				if err != nil || attrs == nil {
					return ""
				}
				return attrs.ActiveOwnerAttrs[ipam.AttributePod]
			}
		}

		It("should follow the mainline migration flow, with GARP detection and IPAM owner swap", func() {
			srcRouteFn := lmWorkloadRoute(tc.Felixes[0], source)
			tgtRouteFn := lmWorkloadRoute(tc.Felixes[1], target)

			By("programming a normal-priority route for the source pod")
			Eventually(srcRouteFn, "10s", "200ms").Should(ContainSubstring(lmNormalMetric))
			lmExpectReachableVia(tc.Felixes[0], source)

			By("seeding the VM's IPAM allocation, as the CNI plugin would have")
			ip, _ := seedVMIPAM()

			By("creating the VMIM and then the target pod")
			targetSeen := lmWatchForState(tc.Felixes[1], "Target")
			vmim := createVMIM("migration-1", kubevirtv1.MigrationRunning, source.Name)
			configureTargetPod(vmim)

			By("suppressing the target pod's route while awaiting the GARP")
			Eventually(targetSeen, "10s").Should(BeClosed())
			Consistently(tgtRouteFn, "3s", "500ms").Should(BeEmpty(),
				"target route should be suppressed before the target VM is live")
			Expect(srcRouteFn()).To(ContainSubstring(lmNormalMetric),
				"source route should be untouched during migration")

			// Unlike in the OpenStack-style suite, the VM's IP is still reachable from
			// the target host here: the seeded IPAM block is affine to the source node
			// and the source pod is the active owner, so Felix routes the traffic to
			// the source host, where the still-live source VM answers.  That is the
			// intended during-migration behaviour.
			lmExpectReachableVia(tc.Felixes[1], target)

			By("programming an elevated-priority route when the target sends a GARP")
			lmGARPElicitsRoute(tc.Felixes[1], target, lmElevatedMetric)
			lmExpectReachableVia(tc.Felixes[1], target)

			By("swapping the IPAM owner attributes to make the target pod the active owner")
			Eventually(activeOwnerPod(ip), "10s", "500ms").Should(Equal(target.Name))

			By("completing the migration: VMIM succeeds and the source pod is removed")
			setVMIMPhase("migration-1", kubevirtv1.MigrationSucceeded)
			source.RemoveFromInfra(infra)

			By("keeping the elevated route until the convergence time has elapsed")
			Consistently(tgtRouteFn, "3s", "500ms").Should(ContainSubstring(lmElevatedMetric))
			Eventually(srcRouteFn, "10s", "200ms").Should(BeEmpty(),
				"source route should be removed with the source pod")
			Eventually(tgtRouteFn, "15s", "500ms").Should(ContainSubstring(lmNormalMetric))
			lmExpectReachableVia(tc.Felixes[1], target)
		})

		It("should handle migration failure", func() {
			srcRouteFn := lmWorkloadRoute(tc.Felixes[0], source)
			tgtRouteFn := lmWorkloadRoute(tc.Felixes[1], target)

			By("creating the VMIM and then the target pod")
			targetSeen := lmWatchForState(tc.Felixes[1], "Target")
			vmim := createVMIM("migration-1", kubevirtv1.MigrationRunning, source.Name)
			configureTargetPod(vmim)
			Eventually(targetSeen, "10s").Should(BeClosed())
			Consistently(tgtRouteFn, "3s", "500ms").Should(BeEmpty())

			By("keeping the target's route suppressed when the migration fails")
			// A Failed VMIM still identifies the target pod, and the target VM never
			// became live, so the route must stay suppressed until KubeVirt tears the
			// target pod down.
			setVMIMPhase("migration-1", kubevirtv1.MigrationFailed)
			Consistently(tgtRouteFn, "3s", "500ms").Should(BeEmpty())

			By("never programming a route for the target once it is torn down")
			baseSeen := lmWatchForState(tc.Felixes[1], "Base")
			target.RemoveFromInfra(infra)
			Eventually(baseSeen, "10s").Should(BeClosed())
			Consistently(tgtRouteFn, "3s", "500ms").Should(BeEmpty())

			By("leaving the source untouched throughout")
			Expect(srcRouteFn()).To(ContainSubstring(lmNormalMetric))
			lmExpectReachableVia(tc.Felixes[0], source)
		})
	})

// lmEnsureVMIMCRD ensures that the KubeVirt VirtualMachineInstanceMigration CRD is installed and
// established in the FV API server.  The CRD is a trimmed stand-in for the real KubeVirt one: a
// free-form schema, and no status subresource so that tests can write spec and status in a single
// create/update.
func lmEnsureVMIMCRD(restConfig *rest.Config) {
	apiExtClient, err := apiextensionsclient.NewForConfig(restConfig)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	crd := &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "virtualmachineinstancemigrations.kubevirt.io"},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: "kubevirt.io",
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Plural:     "virtualmachineinstancemigrations",
				Singular:   "virtualmachineinstancemigration",
				Kind:       "VirtualMachineInstanceMigration",
				ListKind:   "VirtualMachineInstanceMigrationList",
				ShortNames: []string{"vmim"},
			},
			Scope: apiextensionsv1.NamespaceScoped,
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{{
				Name:    "v1",
				Served:  true,
				Storage: true,
				Schema: &apiextensionsv1.CustomResourceValidation{
					OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
						Type:                   "object",
						XPreserveUnknownFields: ptr.To(true),
					},
				},
			}},
		},
	}
	_, err = apiExtClient.ApiextensionsV1().CustomResourceDefinitions().Create(
		context.Background(), crd, metav1.CreateOptions{})
	if err != nil && !k8serrors.IsAlreadyExists(err) {
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
	}

	EventuallyWithOffset(1, func() bool {
		got, err := apiExtClient.ApiextensionsV1().CustomResourceDefinitions().Get(
			context.Background(), crd.Name, metav1.GetOptions{})
		if err != nil {
			return false
		}
		for _, cond := range got.Status.Conditions {
			if cond.Type == apiextensionsv1.Established && cond.Status == apiextensionsv1.ConditionTrue {
				return true
			}
		}
		return false
	}, "10s", "200ms").Should(BeTrue(), "VMIM CRD did not become established")
}
