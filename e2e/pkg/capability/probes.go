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

package capability

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
)

// finding is what one probe saw. detail says why, for the lane's log.
type finding struct {
	present   bool
	unchecked bool
	detail    string
}

func present(format string, args ...any) finding {
	return finding{present: true, detail: fmt.Sprintf(format, args...)}
}

func absent(format string, args ...any) finding {
	return finding{detail: fmt.Sprintf(format, args...)}
}

func unchecked(format string, args ...any) finding {
	return finding{unchecked: true, detail: fmt.Sprintf(format, args...)}
}

// probe decides whether the cluster has one capability. It returns an error
// only when the API failed in a way that says nothing about the capability.
type probe func(ctx context.Context, c *Cluster) (finding, error)

// probes holds one probe per capability in All.
var probes = map[Capability]probe{
	Operator:      probeOperator,
	CalicoCNI:     fromInstallation(cniIs(operatorv1.PluginCalico)),
	CalicoIPAM:    fromInstallation(ipamIs(operatorv1.IPAMPluginCalico)),
	AzureIPAM:     fromInstallation(ipamIs(operatorv1.IPAMPluginAzureVNET)),
	AggregatedAPI: probeCalicoAPIService(true),
	V3CRDs:        probeCalicoAPIService(false),
	BGP:           fromInstallation(bgpEnabled),
	BGPRouting:    probeBGPRouting,
	BGPMesh:       probeBGPMesh,
	NoEncap:       probeNoEncap,
	BPF:           fromInstallation(dataplaneIn(operatorv1.LinuxDataplaneBPF)),
	BPFDSR:        probeBPFDSR,
	Xtables:       fromInstallation(dataplaneIn(operatorv1.LinuxDataplaneIptables, operatorv1.LinuxDataplaneNftables)),
	PolicyTiers:   fromInstallation(dataplaneIn(operatorv1.LinuxDataplaneIptables, operatorv1.LinuxDataplaneNftables, operatorv1.LinuxDataplaneBPF)),
	DoNotTrack:    fromInstallation(dataplaneIn(operatorv1.LinuxDataplaneIptables, operatorv1.LinuxDataplaneNftables, operatorv1.LinuxDataplaneBPF)),
	WireGuard:     probeWireGuard,
	HostPorts:     fromInstallation(hostPortsEnabled),
	CalicoMTU:     probeCalicoMTU,
	AutoHEPs:      onTrust("a lane choice: the specs turn auto host endpoints on themselves"),
	Goldmane:      probeGoldmane,
	AWS:           nodeProviderIs("aws://"),
	Azure:         nodeProviderIs("azure://"),
	RKE2:          everyNode("runs an RKE2 kubelet", runsRKE2),
	OpenShift:     probeOpenShift,
	RHEL:          everyNode("runs RHEL", runsRHEL),
	IPv4:          everyNode("has an IPv4 internal address", hasInternalIP(false)),
	IPv6:          everyNode("has an IPv6 internal address", hasInternalIP(true)),
	KubeVirt:      probeKubeVirt,
	RealKubeVirt:  kubeVirtSimulated(false),
	MockVirt:      kubeVirtSimulated(true),
	Istio:         probeIstio,
	ExternalNode:  probeExternalNode,

	RoutableIPPools:       onTrust("a cloud network property: routing a pool's addresses depends on the VPC, not Calico"),
	NodePortAcrossNodes:   onTrust("a cloud network property: the platform's security groups decide it"),
	HostNetworkServices:   onTrust("seen only by running traffic from a host-networked pod"),
	HostEndpointCrossNode: onTrust("seen only by running traffic through a host endpoint policy"),
	RapidClientImage:      onTrust("whether a node can pull the image is seen only by scheduling it"),
	ConnectionLimits:      onTrust("seen only by opening connections past the limit"),
	AmbientPolicy:         onTrust("seen only by running traffic through ambient mode"),
}

// probeOperator passes when tigera-operator manages Calico, which is exactly
// when the Installation exists.
func probeOperator(ctx context.Context, c *Cluster) (finding, error) {
	inst, err := installation(ctx, c)
	if err != nil {
		return finding{}, err
	}
	if inst == nil {
		return absent("no Installation named default"), nil
	}
	return present("Installation default exists"), nil
}

// installationCheck decides a capability from the configuration the operator
// computed, with every default filled in.
type installationCheck func(inst *operatorv1.Installation) finding

// fromInstallation turns an Installation check into a probe. A cluster with no
// Installation, such as a manifest install, leaves the capability unchecked,
// since the probe can't tell "not installed" from "not operator managed".
func fromInstallation(check installationCheck) probe {
	return func(ctx context.Context, c *Cluster) (finding, error) {
		inst, err := installation(ctx, c)
		if err != nil {
			return finding{}, err
		}
		if inst == nil {
			return unchecked("no Installation to read"), nil
		}
		if inst.Status.Computed == nil {
			return absent("the operator hasn't computed the Installation yet"), nil
		}
		return check(inst), nil
	}
}

// installation reads the Installation, returning nil when the cluster has none
// or doesn't serve the operator API at all.
func installation(ctx context.Context, c *Cluster) (*operatorv1.Installation, error) {
	inst := &operatorv1.Installation{}
	err := c.client.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, inst)
	if notServedOrNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read Installation: %w", err)
	}
	return inst, nil
}

// cniIs passes when the computed Installation uses the want CNI plugin.
func cniIs(want operatorv1.CNIPluginType) installationCheck {
	return func(inst *operatorv1.Installation) finding {
		cni := inst.Status.Computed.CNI
		if cni != nil && cni.Type == want {
			return present("CNI plugin is %s", want)
		}
		return absent("CNI plugin is %s, not %s", cniType(inst), want)
	}
}

func cniType(inst *operatorv1.Installation) string {
	if cni := inst.Status.Computed.CNI; cni != nil {
		return string(cni.Type)
	}
	return "unset"
}

// ipamIs passes when the computed Installation uses the want IPAM plugin.
func ipamIs(want operatorv1.IPAMPluginType) installationCheck {
	return func(inst *operatorv1.Installation) finding {
		cni := inst.Status.Computed.CNI
		if cni != nil && cni.IPAM != nil && cni.IPAM.Type == want {
			return present("IPAM plugin is %s", want)
		}
		got := "unset"
		if cni != nil && cni.IPAM != nil {
			got = string(cni.IPAM.Type)
		}
		return absent("IPAM plugin is %s, not %s", got, want)
	}
}

// bgpEnabled passes when the computed Installation turns BGP on.
func bgpEnabled(inst *operatorv1.Installation) finding {
	network := inst.Status.Computed.CalicoNetwork
	if network != nil && network.BGP != nil && *network.BGP == operatorv1.BGPEnabled {
		return present("Installation has BGP enabled")
	}
	return absent("Installation has BGP disabled")
}

// dataplaneIn passes when the Linux dataplane is one of want. The operator
// leaves it unset for iptables.
func dataplaneIn(want ...operatorv1.LinuxDataplaneOption) installationCheck {
	return func(inst *operatorv1.Installation) finding {
		got := linuxDataplane(inst)
		if slices.Contains(want, got) {
			return present("Linux dataplane is %s", got)
		}
		return absent("Linux dataplane is %s", got)
	}
}

func linuxDataplane(inst *operatorv1.Installation) operatorv1.LinuxDataplaneOption {
	network := inst.Status.Computed.CalicoNetwork
	if network == nil || network.LinuxDataplane == nil {
		return operatorv1.LinuxDataplaneIptables
	}
	return *network.LinuxDataplane
}

// hostPortsEnabled passes when the operator adds the portmap plugin, which it
// does only for the Calico CNI with host ports on.
func hostPortsEnabled(inst *operatorv1.Installation) finding {
	if f := cniIs(operatorv1.PluginCalico)(inst); !f.present {
		return f
	}
	network := inst.Status.Computed.CalicoNetwork
	if network != nil && network.HostPorts != nil && *network.HostPorts == operatorv1.HostPortsEnabled {
		return present("Calico CNI with host ports enabled")
	}
	return absent("Installation has host ports disabled")
}

// probeCalicoMTU passes when Calico renders the pod MTU and the operator has
// published the value the specs compare against.
func probeCalicoMTU(ctx context.Context, c *Cluster) (finding, error) {
	return fromInstallation(func(inst *operatorv1.Installation) finding {
		if f := cniIs(operatorv1.PluginCalico)(inst); !f.present {
			return f
		}
		if inst.Status.MTU <= 0 {
			return absent("the Installation reports no MTU")
		}
		return present("Installation reports MTU %d", inst.Status.MTU)
	})(ctx, c)
}

// calicoAPIServiceName is registered both by calico-apiserver and, for CRDs,
// by kube-apiserver itself. Only the first has a backing Service.
const calicoAPIServiceName = "v3.projectcalico.org"

// probeCalicoAPIService tells the two ways projectcalico.org/v3 is served
// apart. Discovery can't, since the group is served in both modes.
func probeCalicoAPIService(aggregated bool) probe {
	return func(ctx context.Context, c *Cluster) (finding, error) {
		apiService := &apiregistrationv1.APIService{}
		err := c.client.Get(ctx, ctrlclient.ObjectKey{Name: calicoAPIServiceName}, apiService)
		if notServedOrNotFound(err) {
			return absent("projectcalico.org/v3 isn't served"), nil
		}
		if err != nil {
			return finding{}, fmt.Errorf("read APIService %s: %w", calicoAPIServiceName, err)
		}

		served := apiService.Spec.Service != nil
		mode := "kube-apiserver from CRDs"
		if served {
			mode = "calico-apiserver"
		}
		if served == aggregated {
			return present("projectcalico.org/v3 is served by %s", mode), nil
		}
		return absent("projectcalico.org/v3 is served by %s", mode), nil
	}
}

// probeBGPRouting passes when BGP programs the cluster's pod routes. In Felix
// routing mode BIRD still runs, but Felix programs the routes instead.
func probeBGPRouting(ctx context.Context, c *Cluster) (finding, error) {
	f, err := fromInstallation(bgpEnabled)(ctx, c)
	if err != nil || !f.present {
		return f, err
	}
	felixConfig, f, err := felixConfiguration(ctx, c)
	if felixConfig == nil {
		return f, err
	}
	if felixConfig.Spec.ProgramClusterRoutes != nil && *felixConfig.Spec.ProgramClusterRoutes == v3.Enabled {
		return absent("Felix programs cluster routes"), nil
	}
	return present("BGP programs cluster routes"), nil
}

// probeBGPMesh passes when the node-to-node mesh is the only path between
// nodes: BGP on, the mesh on, and no pool tunneling over VXLAN.
func probeBGPMesh(ctx context.Context, c *Cluster) (finding, error) {
	bgp, err := fromInstallation(bgpEnabled)(ctx, c)
	if err != nil || !bgp.present {
		return bgp, err
	}

	bgpConfig := &v3.BGPConfiguration{}
	err = c.client.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, bgpConfig)
	if err != nil && !notServedOrNotFound(err) {
		return finding{}, fmt.Errorf("read BGPConfiguration: %w", err)
	}
	if err == nil && bgpConfig.Spec.NodeToNodeMeshEnabled != nil && !*bgpConfig.Spec.NodeToNodeMeshEnabled {
		return absent("the node-to-node mesh is disabled"), nil
	}

	pools, poolsFinding, err := enabledIPPools(ctx, c)
	if pools == nil {
		return poolsFinding, err
	}
	for _, p := range pools {
		if p.Spec.VXLANMode != "" && p.Spec.VXLANMode != v3.VXLANModeNever {
			return absent("IP pool %s uses VXLAN, a path besides the mesh", p.Name), nil
		}
	}
	return present("BGP mesh is the only path between nodes"), nil
}

// probeNoEncap passes when no enabled IP pool encapsulates.
func probeNoEncap(ctx context.Context, c *Cluster) (finding, error) {
	pools, f, err := enabledIPPools(ctx, c)
	if pools == nil {
		return f, err
	}
	for _, p := range pools {
		if p.Spec.IPIPMode != "" && p.Spec.IPIPMode != v3.IPIPModeNever {
			return absent("IP pool %s uses IPIP", p.Name), nil
		}
		if p.Spec.VXLANMode != "" && p.Spec.VXLANMode != v3.VXLANModeNever {
			return absent("IP pool %s uses VXLAN", p.Name), nil
		}
	}
	return present("no enabled IP pool encapsulates"), nil
}

// enabledIPPools lists the pools in use. When it can't, it returns nil pools
// and the finding the caller should report instead.
func enabledIPPools(ctx context.Context, c *Cluster) ([]v3.IPPool, finding, error) {
	list := &v3.IPPoolList{}
	err := c.client.List(ctx, list)
	if notServedOrNotFound(err) {
		return nil, unchecked("projectcalico.org/v3 isn't served"), nil
	}
	if err != nil {
		return nil, finding{}, fmt.Errorf("list IP pools: %w", err)
	}

	pools := slices.DeleteFunc(list.Items, func(p v3.IPPool) bool { return p.Spec.Disabled })
	if len(pools) == 0 {
		return nil, absent("no enabled IP pools"), nil
	}
	return pools, finding{}, nil
}

// probeBPFDSR passes when the BPF dataplane sends external service replies
// straight from the backend's node.
func probeBPFDSR(ctx context.Context, c *Cluster) (finding, error) {
	f, err := fromInstallation(dataplaneIn(operatorv1.LinuxDataplaneBPF))(ctx, c)
	if err != nil || !f.present {
		return f, err
	}
	felixConfig, f, err := felixConfiguration(ctx, c)
	if felixConfig == nil {
		return f, err
	}
	if strings.EqualFold(felixConfig.Spec.BPFExternalServiceMode, "DSR") {
		return present("BPF external service mode is DSR"), nil
	}
	return absent("BPF external service mode is %q", felixConfig.Spec.BPFExternalServiceMode), nil
}

// probeWireGuard passes when Felix has WireGuard on for either IP family.
func probeWireGuard(ctx context.Context, c *Cluster) (finding, error) {
	felixConfig, f, err := felixConfiguration(ctx, c)
	if felixConfig == nil {
		return f, err
	}
	spec := felixConfig.Spec
	if (spec.WireguardEnabled != nil && *spec.WireguardEnabled) || (spec.WireguardEnabledV6 != nil && *spec.WireguardEnabledV6) {
		return present("FelixConfiguration has WireGuard enabled"), nil
	}
	return absent("FelixConfiguration has WireGuard disabled"), nil
}

// felixConfiguration reads the default FelixConfiguration. When it can't, it
// returns nil and the finding the caller should report instead.
func felixConfiguration(ctx context.Context, c *Cluster) (*v3.FelixConfiguration, finding, error) {
	felixConfig := &v3.FelixConfiguration{}
	err := c.client.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, felixConfig)
	if notServedOrNotFound(err) {
		return nil, unchecked("no FelixConfiguration named default to read"), nil
	}
	if err != nil {
		return nil, finding{}, fmt.Errorf("read FelixConfiguration: %w", err)
	}
	return felixConfig, finding{}, nil
}

// probeGoldmane passes when the operator reports Goldmane available. The
// Goldmane resource's own status is never written, so TigeraStatus is read.
func probeGoldmane(ctx context.Context, c *Cluster) (finding, error) {
	ts := &operatorv1.TigeraStatus{}
	err := c.client.Get(ctx, ctrlclient.ObjectKey{Name: "goldmane"}, ts)
	if notServedOrNotFound(err) {
		return absent("no TigeraStatus named goldmane"), nil
	}
	if err != nil {
		return finding{}, fmt.Errorf("read TigeraStatus goldmane: %w", err)
	}
	if !ts.Available() {
		return absent("TigeraStatus goldmane isn't Available"), nil
	}
	return present("TigeraStatus goldmane is Available"), nil
}

// nodeProviderIs passes when every node's provider ID has the cloud's scheme.
// Nodes without a cloud provider have no provider ID, which says nothing
// about where they run, so the capability is left unchecked.
func nodeProviderIs(scheme string) probe {
	byScheme := everyNode("has a "+scheme+" provider ID", func(n corev1.Node) bool {
		return strings.HasPrefix(n.Spec.ProviderID, scheme)
	})
	return func(ctx context.Context, c *Cluster) (finding, error) {
		nodes := &corev1.NodeList{}
		if err := c.client.List(ctx, nodes); err != nil {
			return finding{}, fmt.Errorf("list nodes: %w", err)
		}
		if slices.ContainsFunc(nodes.Items, func(n corev1.Node) bool { return n.Spec.ProviderID == "" }) {
			return unchecked("a node has no provider ID, so its cloud is unknown"), nil
		}
		return byScheme(ctx, c)
	}
}

// nodeTest is a fact about one node.
type nodeTest func(n corev1.Node) bool

// everyNode passes when every node satisfies test. what describes the test
// for the lane's log.
func everyNode(what string, test nodeTest) probe {
	return func(ctx context.Context, c *Cluster) (finding, error) {
		nodes := &corev1.NodeList{}
		if err := c.client.List(ctx, nodes); err != nil {
			return finding{}, fmt.Errorf("list nodes: %w", err)
		}
		if len(nodes.Items) == 0 {
			return absent("the cluster has no nodes"), nil
		}
		for _, n := range nodes.Items {
			if !test(n) {
				return absent("node %s doesn't: %s", n.Name, what), nil
			}
		}
		return present("every node %s", what), nil
	}
}

// runsRKE2 reads the kubelet version, which RKE2 suffixes with +rke2.
func runsRKE2(n corev1.Node) bool {
	return strings.Contains(n.Status.NodeInfo.KubeletVersion, "rke2")
}

func runsRHEL(n corev1.Node) bool {
	return strings.HasPrefix(n.Status.NodeInfo.OSImage, "Red Hat Enterprise Linux")
}

// hasInternalIP passes for a node with an internal address in the IPv6 family
// when v6 is set, and in the IPv4 family otherwise.
func hasInternalIP(v6 bool) nodeTest {
	return func(n corev1.Node) bool {
		for _, a := range n.Status.Addresses {
			if a.Type != corev1.NodeInternalIP {
				continue
			}
			if ip := net.ParseIP(a.Address); ip != nil && (ip.To4() == nil) == v6 {
				return true
			}
		}
		return false
	}
}

const openShiftConfigGroup = "config.openshift.io"

// probeOpenShift passes when the cluster serves OpenShift's config API group.
func probeOpenShift(ctx context.Context, c *Cluster) (finding, error) {
	served, err := groupServed(c, openShiftConfigGroup)
	if err != nil || !served {
		return absent("%s isn't served", openShiftConfigGroup), err
	}
	return present("%s is served", openShiftConfigGroup), nil
}

// kubeVirtGroup is served by real KubeVirt and by its simulated MockVirt alike.
const kubeVirtGroup = "kubevirt.io"

// probeKubeVirt passes when the cluster serves the KubeVirt API group.
func probeKubeVirt(ctx context.Context, c *Cluster) (finding, error) {
	served, err := groupServed(c, kubeVirtGroup)
	if err != nil || !served {
		return absent("%s isn't served", kubeVirtGroup), err
	}
	return present("%s is served", kubeVirtGroup), nil
}

// kubeVirtSimulated tells real KubeVirt from MockVirt by the KubeVirt
// resource's simulation mode, the switch MockVirt turns on.
func kubeVirtSimulated(want bool) probe {
	return func(ctx context.Context, c *Cluster) (finding, error) {
		kubeVirt := &unstructured.Unstructured{}
		kubeVirt.SetGroupVersionKind(schema.GroupVersionKind{Group: kubeVirtGroup, Version: "v1", Kind: "KubeVirt"})
		err := c.client.Get(ctx, ctrlclient.ObjectKey{Namespace: "kubevirt", Name: "kubevirt"}, kubeVirt)
		if notServedOrNotFound(err) {
			return absent("no KubeVirt resource kubevirt/kubevirt"), nil
		}
		if err != nil {
			return finding{}, fmt.Errorf("read KubeVirt: %w", err)
		}

		simulated, _, err := unstructured.NestedBool(kubeVirt.Object, "spec", "configuration", "developerConfiguration", "simulationMode")
		if err != nil {
			return finding{}, fmt.Errorf("read KubeVirt simulation mode: %w", err)
		}
		if simulated == want {
			return present("KubeVirt simulation mode is %t", simulated), nil
		}
		return absent("KubeVirt simulation mode is %t", simulated), nil
	}
}

// probeIstio passes when the operator can install Istio ambient mode, which
// the specs turn on themselves, on a dataplane that enforces policy with it.
func probeIstio(ctx context.Context, c *Cluster) (finding, error) {
	resources, err := c.discovery.ServerResourcesForGroupVersion(operatorv1.GroupVersion.String())
	if err != nil && !notServedOrNotFound(err) {
		return finding{}, fmt.Errorf("discover %s: %w", operatorv1.GroupVersion, err)
	}
	if resources == nil || !slices.ContainsFunc(resources.APIResources, func(r metav1.APIResource) bool { return r.Name == "istios" }) {
		return absent("the operator doesn't serve Istio resources"), nil
	}
	return fromInstallation(func(inst *operatorv1.Installation) finding {
		if dp := linuxDataplane(inst); dp == operatorv1.LinuxDataplaneBPF {
			return absent("Istio ambient policy isn't enforced on the BPF dataplane")
		}
		return present("the operator serves Istio resources")
	})(ctx, c)
}

// probeExternalNode passes when the lane supplied the external node's address.
func probeExternalNode(_ context.Context, c *Cluster) (finding, error) {
	if c.extNodeIP == "" {
		return absent("EXT_IP is unset"), nil
	}
	return present("EXT_IP is %s", c.extNodeIP), nil
}

// onTrust is the probe for a capability no API reports, which the check
// accepts as declared.
func onTrust(why string) probe {
	return func(context.Context, *Cluster) (finding, error) {
		return unchecked("declared on trust, %s", why), nil
	}
}

// groupServed reports whether discovery lists the API group.
func groupServed(c *Cluster, group string) (bool, error) {
	groups, err := c.discovery.ServerGroups()
	if err != nil {
		return false, fmt.Errorf("discover API groups: %w", err)
	}
	return slices.ContainsFunc(groups.Groups, func(g metav1.APIGroup) bool { return g.Name == group }), nil
}

// notServedOrNotFound reports whether err means the object or its whole API
// is absent, rather than that the read failed.
func notServedOrNotFound(err error) bool {
	return err != nil && (apierrors.IsNotFound(err) || meta.IsNoMatchError(err))
}
