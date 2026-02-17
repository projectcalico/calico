// Copyright (c) 2021-2025 Tigera, Inc. All rights reserved.
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
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/ifstate"
	"github.com/projectcalico/calico/felix/bpf/ipsets"
	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/bpf/nat"
	. "github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/felix/proto"
)

// typeMetaV1 creates a TypeMeta for the given kind with API version v1.
func typeMetaV1(kind string) metav1.TypeMeta {
	return metav1.TypeMeta{
		Kind:       kind,
		APIVersion: "v1",
	}
}

// objectMetaV1 creates an ObjectMeta with the given name in the default namespace.
func objectMetaV1(name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name:        name,
		Namespace:   "default",
		Annotations: make(map[string]string),
	}
}

// dumpNATmaps dumps NAT maps from all Felix instances concurrently.
func dumpNATmaps(felixes []*infrastructure.Felix) ([]nat.MapMem, []nat.BackendMapMem, []nat.MaglevMapMem) {
	bpfsvcs := make([]nat.MapMem, len(felixes))
	bpfeps := make([]nat.BackendMapMem, len(felixes))
	bpfcheps := make([]nat.MaglevMapMem, len(felixes))

	// Felixes are independent, we can dump the maps  concurrently
	var wg sync.WaitGroup

	for i := range felixes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer GinkgoRecover()
			bpfsvcs[i], bpfeps[i], bpfcheps[i] = dumpNATMaps(felixes[i])
		}(i)
	}

	wg.Wait()

	return bpfsvcs, bpfeps, bpfcheps
}

// dumpNATmapsAny dumps NAT maps from all Felix instances concurrently using interface types.
func dumpNATmapsAny(family int, felixes []*infrastructure.Felix) (
	[]map[nat.FrontendKeyInterface]nat.FrontendValue,
	[]map[nat.BackendKey]nat.BackendValueInterface,
	[]map[nat.MaglevBackendKeyInterface]nat.BackendValueInterface,
) {
	bpfsvcs := make([]map[nat.FrontendKeyInterface]nat.FrontendValue, len(felixes))
	bpfeps := make([]map[nat.BackendKey]nat.BackendValueInterface, len(felixes))
	bpfcheps := make([]map[nat.MaglevBackendKeyInterface]nat.BackendValueInterface, len(felixes))

	// Felixes are independent, we can dump the maps  concurrently
	var wg sync.WaitGroup

	for i := range felixes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer GinkgoRecover()
			bpfsvcs[i], bpfeps[i], bpfcheps[i] = dumpNATMapsAny(family, felixes[i])
		}(i)
	}

	wg.Wait()

	return bpfsvcs, bpfeps, bpfcheps
}

// dumpNATmapsV6 dumps IPv6 NAT maps from all Felix instances concurrently.
func dumpNATmapsV6(felixes []*infrastructure.Felix) ([]nat.MapMemV6, []nat.BackendMapMemV6, []nat.MaglevMapMemV6) {
	bpfsvcs := make([]nat.MapMemV6, len(felixes))
	bpfeps := make([]nat.BackendMapMemV6, len(felixes))
	cheps := make([]nat.MaglevMapMemV6, len(felixes))

	// Felixes are independent, we can dump the maps  concurrently
	var wg sync.WaitGroup

	for i := range felixes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer GinkgoRecover()
			bpfsvcs[i], bpfeps[i], cheps[i] = dumpNATMapsV6(felixes[i])
		}(i)
	}

	wg.Wait()

	return bpfsvcs, bpfeps, cheps
}

// dumpNATMaps dumps all NAT-related maps from a single Felix instance.
func dumpNATMaps(felix *infrastructure.Felix) (nat.MapMem, nat.BackendMapMem, nat.MaglevMapMem) {
	return dumpNATMap(felix), dumpEPMap(felix), dumpMaglevMap(felix)
}

// dumpNATMapsV6 dumps all IPv6 NAT-related maps from a single Felix instance.
func dumpNATMapsV6(felix *infrastructure.Felix) (nat.MapMemV6, nat.BackendMapMemV6, nat.MaglevMapMemV6) {
	return dumpNATMapV6(felix), dumpEPMapV6(felix), dumpMaglevMapV6(felix)
}

// dumpNATMapsAny dumps NAT maps using interface types for the specified IP family.
func dumpNATMapsAny(family int, felix *infrastructure.Felix) (
	map[nat.FrontendKeyInterface]nat.FrontendValue,
	map[nat.BackendKey]nat.BackendValueInterface,
	map[nat.MaglevBackendKeyInterface]nat.BackendValueInterface,
) {
	f := make(map[nat.FrontendKeyInterface]nat.FrontendValue)
	b := make(map[nat.BackendKey]nat.BackendValueInterface)
	m := make(map[nat.MaglevBackendKeyInterface]nat.BackendValueInterface)

	if family == 6 {
		f6, b6, m6 := dumpNATMapsV6(felix)
		for k, v := range f6 {
			f[k] = v
		}
		for k, v := range b6 {
			b[k] = v
		}
		for k, v := range m6 {
			m[k] = v
		}
	} else {
		f4, b4, m4 := dumpNATMaps(felix)
		for k, v := range f4 {
			f[k] = v
		}
		for k, v := range b4 {
			b[k] = v
		}
		for k, v := range m4 {
			m[k] = v
		}
	}

	return f, b, m
}

// dumpCTMapsAny dumps conntrack maps using interface types for the specified IP family.
func dumpCTMapsAny(family int, felix *infrastructure.Felix) map[conntrack.KeyInterface]conntrack.ValueInterface {
	m := make(map[conntrack.KeyInterface]conntrack.ValueInterface)

	if family == 4 {
		ctMap := dumpCTMap(felix)
		for k, v := range ctMap {
			m[k] = v
		}
	} else {
		ctMap := dumpCTMapV6(felix)
		for k, v := range ctMap {
			m[k] = v
		}
	}
	return m
}

// dumpBPFMap is a generic helper to dump a BPF map from a Felix instance.
func dumpBPFMap(felix *infrastructure.Felix, m maps.Map, iter func(k, v []byte)) {
	// Wait for the map to exist before trying to access it.  Otherwise, we
	// might fail a test that was retrying this dump anyway.
	Eventually(func() bool {
		return felix.FileExists(m.Path())
	}, "10s", "300ms").Should(BeTrue(), fmt.Sprintf("dumpBPFMap: map %s didn't show up inside container", m.Path()))
	cmd, err := maps.DumpMapCmd(m)
	Expect(err).NotTo(HaveOccurred(), "Failed to get BPF map dump command: "+m.Path())
	log.WithField("cmd", cmd).Debug("dumpBPFMap")
	out, err := felix.ExecOutput(cmd...)
	Expect(err).NotTo(HaveOccurred(), "Failed to get dump BPF map: "+m.Path())
	if strings.Contains(m.(*maps.PinnedMap).Type, "percpu") {
		err = bpf.IterPerCpuMapCmdOutput([]byte(out), iter)
	} else {
		err = bpf.IterMapCmdOutput([]byte(out), iter)
	}
	Expect(err).NotTo(HaveOccurred(), "Failed to parse BPF map dump: "+m.Path())
}

// dumpNATMap dumps the IPv4 NAT frontend map.
func dumpNATMap(felix *infrastructure.Felix) nat.MapMem {
	bm := nat.FrontendMap()
	m := make(nat.MapMem)
	dumpBPFMap(felix, bm, nat.MapMemIter(m))
	return m
}

// dumpEPMap dumps the IPv4 NAT backend map.
func dumpEPMap(felix *infrastructure.Felix) nat.BackendMapMem {
	bm := nat.BackendMap()
	m := make(nat.BackendMapMem)
	dumpBPFMap(felix, bm, nat.BackendMapMemIter(m))
	return m
}

// dumpMaglevMap dumps the IPv4 Maglev map.
func dumpMaglevMap(felix *infrastructure.Felix) nat.MaglevMapMem {
	bm := nat.MaglevMap()
	m := make(nat.MaglevMapMem)
	dumpBPFMap(felix, bm, nat.MaglevMapMemIter(m))
	return m
}

// dumpMaglevMapV6 dumps the IPv6 Maglev map.
func dumpMaglevMapV6(felix *infrastructure.Felix) nat.MaglevMapMemV6 {
	bm := nat.MaglevMapV6()
	m := make(nat.MaglevMapMemV6)
	dumpBPFMap(felix, bm, nat.MaglevMapMemV6Iter(m))
	return m
}

// dumpNATMapV6 dumps the IPv6 NAT frontend map.
func dumpNATMapV6(felix *infrastructure.Felix) nat.MapMemV6 {
	bm := nat.FrontendMapV6()
	m := make(nat.MapMemV6)
	dumpBPFMap(felix, bm, nat.MapMemV6Iter(m))
	return m
}

// dumpEPMapV6 dumps the IPv6 NAT backend map.
func dumpEPMapV6(felix *infrastructure.Felix) nat.BackendMapMemV6 {
	bm := nat.BackendMapV6()
	m := make(nat.BackendMapMemV6)
	dumpBPFMap(felix, bm, nat.BackendMapMemV6Iter(m))
	return m
}

// dumpAffMap dumps the IPv4 affinity map.
func dumpAffMap(felix *infrastructure.Felix) nat.AffinityMapMem {
	bm := nat.AffinityMap()
	m := make(nat.AffinityMapMem)
	dumpBPFMap(felix, bm, nat.AffinityMapMemIter(m))
	return m
}

// dumpAffMapV6 dumps the IPv6 affinity map.
func dumpAffMapV6(felix *infrastructure.Felix) nat.AffinityMapMemV6 {
	bm := nat.AffinityMapV6()
	m := make(nat.AffinityMapMemV6)
	dumpBPFMap(felix, bm, nat.AffinityMapMemV6Iter(m))
	return m
}

// dumpCTMap dumps the IPv4 conntrack map.
func dumpCTMap(felix *infrastructure.Felix) conntrack.MapMem {
	bm := conntrack.Map()
	m := make(conntrack.MapMem)
	dumpBPFMap(felix, bm, conntrack.MapMemIter(m))
	return m
}

// dumpCTMapV6 dumps the IPv6 conntrack map.
func dumpCTMapV6(felix *infrastructure.Felix) conntrack.MapMemV6 {
	bm := conntrack.MapV6()
	m := make(conntrack.MapMemV6)
	dumpBPFMap(felix, bm, conntrack.MapMemIterV6(m))
	return m
}

// dumpSendRecvMap dumps the IPv4 send/recv message map.
func dumpSendRecvMap(felix *infrastructure.Felix) nat.SendRecvMsgMapMem {
	bm := nat.SendRecvMsgMap()
	m := make(nat.SendRecvMsgMapMem)
	dumpBPFMap(felix, bm, nat.SendRecvMsgMapMemIter(m))
	return m
}

// dumpSendRecvMapV6 dumps the IPv6 send/recv message map.
func dumpSendRecvMapV6(felix *infrastructure.Felix) nat.SendRecvMsgMapMemV6 {
	bm := nat.SendRecvMsgMapV6()
	m := make(nat.SendRecvMsgMapMemV6)
	dumpBPFMap(felix, bm, nat.SendRecvMsgMapMemV6Iter(m))
	return m
}

// dumpIfStateMap dumps the interface state map.
func dumpIfStateMap(felix *infrastructure.Felix) ifstate.MapMem {
	im := ifstate.Map()
	m := make(ifstate.MapMem)
	dumpBPFMap(felix, im, ifstate.MapMemIter(m))
	return m
}

// dumpIPSetsMap dumps the IPv4 IP sets map.
func dumpIPSetsMap(felix *infrastructure.Felix) ipsets.MapMem {
	im := ipsets.Map()
	m := make(ipsets.MapMem)
	dumpBPFMap(felix, im, ipsets.MapMemIter(m))
	return m
}

// dumpIPSets6Map dumps the IPv6 IP sets map.
func dumpIPSets6Map(felix *infrastructure.Felix) ipsets.MapMemV6 {
	im := ipsets.MapV6()
	m := make(ipsets.MapMemV6)
	dumpBPFMap(felix, im, ipsets.MapMemV6Iter(m))
	return m
}

// ensureAllNodesBPFProgramsAttached waits for BPF programs to be attached on all Felix instances.
func ensureAllNodesBPFProgramsAttached(felixes []*infrastructure.Felix, ifacesExtra ...string) {
	for _, felix := range felixes {
		ensureBPFProgramsAttachedOffset(2, felix, ifacesExtra...)
	}
}

// ensureBPFProgramsAttached waits for BPF programs to be attached on a Felix instance.
func ensureBPFProgramsAttached(felix *infrastructure.Felix, ifacesExtra ...string) {
	ensureBPFProgramsAttachedOffset(2, felix, ifacesExtra...)
}

// ensureBPFProgramsAttachedOffset waits for BPF programs with a custom stack offset.
func ensureBPFProgramsAttachedOffset(offset int, felix *infrastructure.Felix, ifacesExtra ...string) {
	expectedIfaces := []string{"eth0"}
	if felix.ExpectedIPIPTunnelAddr != "" {
		expectedIfaces = append(expectedIfaces, "tunl0")
	}
	if felix.ExpectedVXLANTunnelAddr != "" {
		expectedIfaces = append(expectedIfaces, "vxlan.calico")
	}
	if felix.ExpectedWireguardTunnelAddr != "" {
		expectedIfaces = append(expectedIfaces, "wireguard.cali")
	}
	if felix.ExpectedWireguardV6TunnelAddr != "" {
		expectedIfaces = append(expectedIfaces, "wg-v6.cali")
	}

	for _, w := range felix.Workloads {
		if w.Runs() {
			if iface := w.GetInterfaceName(); iface != "" {
				expectedIfaces = append(expectedIfaces, iface)
			}
			if iface := w.GetSpoofInterfaceName(); iface != "" {
				expectedIfaces = append(expectedIfaces, iface)
			}
		}
	}

	expectedIfaces = append(expectedIfaces, ifacesExtra...)
	ensureBPFProgramsAttachedOffsetWithIPVersion(offset+1, felix,
		true, felix.TopologyOptions.EnableIPv6,
		expectedIfaces...)
}

// ensureBPFProgramsAttachedOffsetWithIPVersion waits for BPF programs with specific IP version flags.
func ensureBPFProgramsAttachedOffsetWithIPVersion(offset int, felix *infrastructure.Felix, v4, v6 bool, ifaces ...string) {
	var expFlgs uint32

	if v4 {
		expFlgs |= ifstate.FlgIPv4Ready
	}
	if v6 {
		expFlgs |= ifstate.FlgIPv6Ready
	}

	EventuallyWithOffset(offset, func() []string {
		prog := []string{}
		m := dumpIfStateMap(felix)
		for _, v := range m {
			flags := v.Flags()
			if (flags & (ifstate.FlgIPv6Ready | ifstate.FlgIPv4Ready)) == expFlgs {
				prog = append(prog, v.IfName())
			}
		}
		return prog
	}, "1m", "1s").Should(ContainElements(ifaces))
}

// k8sService creates a Kubernetes service pointing to a workload.
func k8sService(name, clusterIP string, w *workload.Workload, port,
	tgtPort int, nodePort int32, protocol string,
) *v1.Service {
	k8sProto := v1.ProtocolTCP
	if protocol == "udp" {
		k8sProto = v1.ProtocolUDP
	}

	svcType := v1.ServiceTypeClusterIP
	if nodePort != 0 {
		svcType = v1.ServiceTypeNodePort
	}

	meta := objectMetaV1(name)
	return &v1.Service{
		TypeMeta:   typeMetaV1("Service"),
		ObjectMeta: meta,
		Spec: v1.ServiceSpec{
			ClusterIP: clusterIP,
			Type:      svcType,
			Selector: map[string]string{
				"name": w.Name,
			},
			Ports: []v1.ServicePort{
				{
					Protocol:   k8sProto,
					Port:       int32(port),
					NodePort:   nodePort,
					Name:       fmt.Sprintf("port-%d", tgtPort),
					TargetPort: intstr.FromInt(tgtPort),
				},
			},
		},
	}
}

// k8sLBService creates a Kubernetes LoadBalancer service.
func k8sLBService(name, clusterIP string, wname string, port,
	tgtPort int, protocol string, externalIPs, srcRange []string,
) *v1.Service {
	k8sProto := v1.ProtocolTCP
	if protocol == "udp" {
		k8sProto = v1.ProtocolUDP
	}

	svcType := v1.ServiceTypeLoadBalancer
	return &v1.Service{
		TypeMeta:   typeMetaV1("Service"),
		ObjectMeta: objectMetaV1(name),
		Spec: v1.ServiceSpec{
			ClusterIP:                clusterIP,
			Type:                     svcType,
			LoadBalancerSourceRanges: srcRange,
			ExternalIPs:              externalIPs,
			Selector: map[string]string{
				"name": wname,
			},
			Ports: []v1.ServicePort{
				{
					Protocol:   k8sProto,
					Port:       int32(port),
					Name:       fmt.Sprintf("port-%d", tgtPort),
					TargetPort: intstr.FromInt(tgtPort),
				},
			},
		},
	}
}

// k8sServiceWithExtIP creates a Kubernetes service with external IPs.
func k8sServiceWithExtIP(name, clusterIP string, w *workload.Workload, port,
	tgtPort int, nodePort int32, protocol string, externalIPs []string,
) *v1.Service {
	k8sProto := v1.ProtocolTCP
	if protocol == "udp" {
		k8sProto = v1.ProtocolUDP
	}

	svcType := v1.ServiceTypeClusterIP
	if nodePort != 0 {
		svcType = v1.ServiceTypeNodePort
	}
	return &v1.Service{
		TypeMeta:   typeMetaV1("Service"),
		ObjectMeta: objectMetaV1(name),
		Spec: v1.ServiceSpec{
			ClusterIP:   clusterIP,
			Type:        svcType,
			ExternalIPs: externalIPs,
			Selector: map[string]string{
				"name": w.Name,
			},
			Ports: []v1.ServicePort{
				{
					Protocol:   k8sProto,
					Port:       int32(port),
					NodePort:   nodePort,
					Name:       fmt.Sprintf("port-%d", tgtPort),
					TargetPort: intstr.FromInt(tgtPort),
				},
			},
		},
	}
}

// k8sGetEpsForService retrieves endpoint slices for a service.
func k8sGetEpsForService(k8s kubernetes.Interface, svc *v1.Service) []discovery.EndpointSlice {
	eps, err := k8s.DiscoveryV1().
		EndpointSlices(svc.Namespace).
		List(context.Background(), metav1.ListOptions{
			LabelSelector: "kubernetes.io/service-name=" + svc.Name,
		})
	Expect(err).NotTo(HaveOccurred())
	return eps.Items
}

// k8sGetEpsForServiceFunc returns a function that retrieves endpoint slices for a service.
func k8sGetEpsForServiceFunc(k8s kubernetes.Interface, svc *v1.Service) func() []discovery.EndpointSlice {
	return func() []discovery.EndpointSlice {
		return k8sGetEpsForService(k8s, svc)
	}
}

// checkSvcEndpoints returns a function that counts total endpoints for a service.
func checkSvcEndpoints(k8s kubernetes.Interface, svc *v1.Service) func() int {
	return func() int {
		epslices := k8sGetEpsForService(k8s, svc)
		totalEps := 0
		for _, eps := range epslices {
			if eps.Endpoints == nil {
				continue
			}
			totalEps += len(eps.Endpoints)
		}
		return totalEps
	}
}

// k8sUpdateService updates a Kubernetes service and waits for endpoints.
func k8sUpdateService(k8sClient kubernetes.Interface, nameSpace, svcName string, oldsvc, newsvc *v1.Service) {
	svc, err := k8sClient.CoreV1().
		Services(nameSpace).
		Get(context.Background(), svcName, metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred())
	log.WithField("origSvc", svc).Info("Read original service before updating it")
	newsvc.ResourceVersion = svc.ResourceVersion
	_, err = k8sClient.CoreV1().Services(nameSpace).Update(context.Background(), newsvc, metav1.UpdateOptions{})
	Expect(err).NotTo(HaveOccurred())
	Eventually(checkSvcEndpoints(k8sClient, oldsvc), "10s").Should(Equal(1),
		"Service endpoints didn't get created? Is controller-manager happy?")
	updatedSvc, err := k8sClient.CoreV1().Services(nameSpace).Get(context.Background(), svcName, metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred())
	log.WithField("updatedSvc", updatedSvc).Info("Read back updated Service")
}

// k8sCreateLBServiceWithEndPoints creates a LoadBalancer service and waits for endpoints.
func k8sCreateLBServiceWithEndPoints(k8sClient kubernetes.Interface, name, clusterIP string, w *workload.Workload, port,
	tgtPort int, protocol string, externalIPs, srcRange []string,
) *v1.Service {
	var (
		testSvc          *v1.Service
		testSvcNamespace string
		epslen           int
	)
	if w != nil {
		testSvc = k8sLBService(name, clusterIP, w.Name, port, tgtPort, protocol, externalIPs, srcRange)
		epslen = 1
	} else {
		testSvc = k8sLBService(name, clusterIP, "nobackend", port, tgtPort, protocol, externalIPs, srcRange)
		epslen = 0
	}
	testSvcNamespace = testSvc.Namespace
	_, err := k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(), testSvc, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
	Eventually(checkSvcEndpoints(k8sClient, testSvc), "10s").Should(Equal(epslen),
		"Service endpoints didn't get created? Is controller-manager happy?")
	return testSvc
}

// checkNodeConntrack verifies that all conntrack entries are related to node addresses.
func checkNodeConntrack(felixes []*infrastructure.Felix) error {
	for i, felix := range felixes {
		conntrackOut, err := felix.ExecOutput("conntrack", "-L")
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "conntrack -L failed")
		lines := strings.Split(conntrackOut, "\n")
	lineLoop:
		for _, line := range lines {
			line = strings.Trim(line, " ")
			if strings.Contains(line, "src=") {
				// Whether traffic is generated in host namespace, or involves NAT, each
				// conntrack entry should be related to node's address
				if strings.Contains(line, felix.GetIP()) {
					continue lineLoop
				}
				if strings.Contains(line, felix.IPv6) {
					continue lineLoop
				}
				if felix.ExpectedIPIPTunnelAddr != "" && strings.Contains(line, felix.ExpectedIPIPTunnelAddr) {
					continue lineLoop
				}
				if felix.ExpectedVXLANTunnelAddr != "" && strings.Contains(line, felix.ExpectedVXLANTunnelAddr) {
					continue lineLoop
				}
				if felix.ExpectedWireguardTunnelAddr != "" && strings.Contains(line, felix.ExpectedWireguardTunnelAddr) {
					continue lineLoop
				}
				if felix.ExpectedVXLANV6TunnelAddr != "" && strings.Contains(line, felix.ExpectedVXLANV6TunnelAddr) {
					continue lineLoop
				}
				if felix.ExpectedWireguardV6TunnelAddr != "" && strings.Contains(line, felix.ExpectedWireguardV6TunnelAddr) {
					continue lineLoop
				}
				// Ignore DHCP
				if strings.Contains(line, "sport=67 dport=68") {
					continue lineLoop
				}
				// Ignore any flows that come from the host itself.  For example, some programs send
				// broadcast probe packets on all interfaces they can see. (Spotify, for example.)
				myAddrs, err := net.InterfaceAddrs()
				Expect(err).NotTo(HaveOccurred())
				for _, a := range myAddrs {
					if strings.Contains(line, a.String()) {
						continue lineLoop
					}
				}
				return fmt.Errorf("unexpected conntrack not from host (felix[%d]): %s", i, line)
			}
		}
	}

	return nil
}

// conntrackCheck returns a function that checks node conntrack entries.
func conntrackCheck(felixes []*infrastructure.Felix) func() error {
	return func() error {
		return checkNodeConntrack(felixes)
	}
}

// conntrackFlushWorkloadEntries returns a function that flushes conntrack entries for workloads.
func conntrackFlushWorkloadEntries(felixes []*infrastructure.Felix) func() {
	return func() {
		for _, felix := range felixes {
			for _, w := range felix.Workloads {
				wIP := w.GetIP()
				if wIP == felix.GetIP() || wIP == felix.GetIPv6() {
					continue // Skip host-networked workloads.
				}
				for _, dirn := range []string{"--orig-src", "--orig-dst", "--reply-dst", "--reply-src"} {
					err := felix.ExecMayFail("conntrack", "-D", dirn, w.GetIP())
					if err != nil && strings.Contains(err.Error(), "0 flow entries have been deleted") {
						// Expected "error" when there are no matching flows.
						continue
					}
					ExpectWithOffset(1, err).NotTo(HaveOccurred(), "conntrack -D failed")
				}
			}
		}
	}
}

// conntrackChecks returns connectivity check options for conntrack verification.
func conntrackChecks(felixes []*infrastructure.Felix) []interface{} {
	if felixes[0].ExpectedIPIPTunnelAddr != "" ||
		felixes[0].ExpectedWireguardTunnelAddr != "" ||
		felixes[0].ExpectedWireguardV6TunnelAddr != "" {
		return nil
	}

	return []interface{}{
		CheckWithInit(conntrackFlushWorkloadEntries(felixes)),
		CheckWithFinalTest(conntrackCheck(felixes)),
		CheckWithBeforeRetry(conntrackFlushWorkloadEntries(felixes)),
	}
}

// setRPF sets reverse path filtering sysctls on all Felix instances.
func setRPF(felixes []*infrastructure.Felix, tunnel string, all, main int) {
	allStr := strconv.Itoa(all)
	mainStr := strconv.Itoa(main)

	var wg sync.WaitGroup

	for _, felix := range felixes {
		wg.Add(1)
		go func(felix *infrastructure.Felix) {
			defer wg.Done()
			Eventually(func() error {
				// N.B. we only support environment with not so strict RPF - can be
				// strict per iface, but not for all.
				if err := felix.ExecMayFail("sysctl", "-w", "net.ipv4.conf.all.rp_filter="+allStr); err != nil {
					return err
				}
				switch tunnel {
				case "none":
					if err := felix.ExecMayFail("sysctl", "-w", "net.ipv4.conf.eth0.rp_filter="+mainStr); err != nil {
						return err
					}
				case "ipip":
					if err := felix.ExecMayFail("sysctl", "-w", "net.ipv4.conf.tunl0.rp_filter="+mainStr); err != nil {
						return err
					}
				case "wireguard":
					if err := felix.ExecMayFail("sysctl", "-w", "net.ipv4.conf.wireguard/cali.rp_filter="+mainStr); err != nil {
						return err
					}
				case "vxlan":
					if err := felix.ExecMayFail("sysctl", "-w", "net.ipv4.conf.vxlan/calico.rp_filter="+mainStr); err != nil {
						return err
					}
				}

				return nil
			}, "5s", "200ms").Should(Succeed())
		}(felix)
	}

	wg.Wait()
}

// checkServiceRoute checks if a service route exists in the Felix routing table.
func checkServiceRoute(felix *infrastructure.Felix, ip string) bool {
	var (
		out string
		err error
	)

	if strings.Contains(ip, ":") && felix.TopologyOptions.EnableIPv6 {
		out, err = felix.ExecOutput("ip", "-6", "route")
	} else {
		out, err = felix.ExecOutput("ip", "route")
	}
	Expect(err).NotTo(HaveOccurred())

	lines := strings.Split(out, "\n")
	rtRE := fmt.Sprintf("%s .* dev bpfin.cali", ip)

	for _, l := range lines {
		if strings.Contains(l, ip) && strings.Contains(l, "dev bpfin.cali") {
			return true
		}
	}
	_ = rtRE // Unused but kept for clarity

	return false
}

// checkIfPolicyOrRuleProgrammed checks if a policy or rule is programmed in BPF.
func checkIfPolicyOrRuleProgrammed(felix *infrastructure.Felix, iface, hook, polName, action string, isWorkload bool, polType string, ipFamily proto.IPVersion) bool {
	startStr := ""
	endStr := ""
	if polType != "" {
		startStr = fmt.Sprintf("Start of %s %s", polType, polName)
		endStr = fmt.Sprintf("End of %s %s", polType, polName)
	}
	actionStr := fmt.Sprintf("Start of rule %s action:\"%s\"", polName, action)
	var policyDbg bpf.PolicyDebugInfo
	out, err := felix.ExecOutput("cat", bpf.PolicyDebugJSONFileName(iface, hook, ipFamily))
	if err != nil {
		return false
	}
	dec := json.NewDecoder(strings.NewReader(string(out)))
	err = dec.Decode(&policyDbg)
	if err != nil {
		return false
	}

	hookStr := "tc ingress"
	if isWorkload {
		if hook == "ingress" {
			hookStr = "tc egress"
		}
	} else {
		if hook == "egress" {
			hookStr = "tc egress"
		}
	}
	if policyDbg.IfaceName != iface || policyDbg.Hook != hookStr || policyDbg.Error != "" {
		return false
	}

	startOfPolicy := false
	endOfPolicy := false
	actionMatch := false

	for _, insn := range policyDbg.PolicyInfo {
		for _, comment := range insn.Comments {
			if strings.Contains(comment, startStr) {
				startOfPolicy = true
			}
			if strings.Contains(comment, actionStr) && startOfPolicy && !endOfPolicy {
				actionMatch = true
			}
			if startOfPolicy && actionMatch && strings.Contains(comment, endStr) {
				endOfPolicy = true
			}
		}
	}

	return (startOfPolicy && endOfPolicy && actionMatch)
}

// bpfCheckIfRuleProgrammed checks if a rule is programmed in BPF policy.
func bpfCheckIfRuleProgrammed(felix *infrastructure.Felix, iface, hook, polName, action string, isWorkload bool) bool {
	return checkIfPolicyOrRuleProgrammed(felix, iface, hook, polName, action, isWorkload, "", proto.IPVersion_IPV4)
}

// bpfCheckIfNetworkPolicyProgrammed checks if a network policy is programmed in BPF.
func bpfCheckIfNetworkPolicyProgrammed(felix *infrastructure.Felix, iface, hook, polNS, polName, action string, isWorkload bool) bool {
	namespacedName := fmt.Sprintf("%s/%s", polNS, polName)
	return checkIfPolicyOrRuleProgrammed(felix, iface, hook, namespacedName, action, isWorkload, "NetworkPolicy", proto.IPVersion_IPV4)
}

// bpfCheckIfGlobalNetworkPolicyProgrammed checks if a global network policy is programmed in BPF.
func bpfCheckIfGlobalNetworkPolicyProgrammed(felix *infrastructure.Felix, iface, hook, polName, action string, isWorkload bool) bool {
	return checkIfPolicyOrRuleProgrammed(felix, iface, hook, polName, action, isWorkload, "GlobalNetworkPolicy", proto.IPVersion_IPV4)
}

// bpfCheckIfGlobalNetworkPolicyProgrammedV6 checks if a global network policy is programmed in BPF for IPv6.
func bpfCheckIfGlobalNetworkPolicyProgrammedV6(felix *infrastructure.Felix, iface, hook, polName, action string, isWorkload bool) bool {
	return checkIfPolicyOrRuleProgrammed(felix, iface, hook, polName, action, isWorkload, "GlobalNetworkPolicy", proto.IPVersion_IPV6)
}

// bpfDumpPolicy dumps BPF policy for an interface.
func bpfDumpPolicy(felix *infrastructure.Felix, iface, hook string) string {
	var (
		out string
		err error
	)

	if felix.TopologyOptions.EnableIPv6 {
		out, err = felix.ExecOutput("calico-bpf", "-6", "policy", "dump", iface, hook, "--asm")
	} else {
		out, err = felix.ExecOutput("calico-bpf", "policy", "dump", iface, hook, "--asm")
	}
	Expect(err).NotTo(HaveOccurred())
	return out
}

// bpfWaitForGlobalNetworkPolicy waits for the given global network policy to appear in BPF policy.
func bpfWaitForGlobalNetworkPolicy(felix *infrastructure.Felix, iface, hook, policyName string) string {
	search := fmt.Sprintf("Start of GlobalNetworkPolicy %s", policyName)
	return bpfWaitForPolicy(felix, iface, hook, search)
}

// bpfWaitForNetworkPolicy waits for the given network policy in the given namespace to appear in BPF policy.
func bpfWaitForNetworkPolicy(felix *infrastructure.Felix, iface, hook, ns, policyName string) string {
	search := fmt.Sprintf("Start of NetworkPolicy %s/%s", ns, policyName)
	return bpfWaitForPolicy(felix, iface, hook, search)
}

// bpfWaitForPolicy waits for the given search string to appear in BPF policy.
func bpfWaitForPolicy(felix *infrastructure.Felix, iface, hook, search string) string {
	out := ""
	EventuallyWithOffset(2, func() string {
		out = bpfDumpPolicy(felix, iface, hook)
		return out
	}, "5s", "200ms").Should(ContainSubstring(search))

	return out
}

// bpfDumpRoutes dumps BPF routes for the appropriate IP family.
func bpfDumpRoutes(felix *infrastructure.Felix) string {
	var (
		out string
		err error
	)

	if felix.TopologyOptions.EnableIPv6 {
		out, err = felix.ExecOutput("calico-bpf", "-6", "routes", "dump")
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
	} else {
		out, err = felix.ExecOutput("calico-bpf", "routes", "dump")
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
	}
	return out
}

// bpfDumpRoutesV4 dumps IPv4 BPF routes.
func bpfDumpRoutesV4(felix *infrastructure.Felix) string {
	out, err := felix.ExecOutput("calico-bpf", "routes", "dump")
	Expect(err).NotTo(HaveOccurred())
	return out
}

// bpfDumpRoutesV6 dumps IPv6 BPF routes.
func bpfDumpRoutesV6(felix *infrastructure.Felix) string {
	out, err := felix.ExecOutput("calico-bpf", "-6", "routes", "dump")
	Expect(err).NotTo(HaveOccurred())
	return out
}
