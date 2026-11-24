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
	"encoding/xml"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/onsi/ginkgo/v2/reporters"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/projectcalico/calico/e2e/pkg/platform"
	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
)

func TestEveryCapabilityHasAProbe(t *testing.T) {
	for _, c := range platform.All {
		if probes[c] == nil {
			t.Errorf("capability %s has no probe, so a lane declaring it can't be checked", c)
		}
	}
	for c := range probes {
		if !slices.Contains(platform.All, c) {
			t.Errorf("probe for %s, which isn't in platform.All, never runs", c)
		}
	}
}

func TestCheckFailsOnADeclaredCapabilityTheClusterLacks(t *testing.T) {
	cluster := fakeCluster(t, operatorInstall(operatorv1.LinuxDataplaneIptables))

	result := Check(context.Background(), cluster, Declarations{platform.BPF: {"cluster/dataplane/bpf.yaml"}})

	if !result.Failed() {
		t.Fatalf("expected failure, got:\n%s", result.Summary())
	}
	want := Miss{Capability: platform.BPF, DeclaredBy: []string{"cluster/dataplane/bpf.yaml"}, Saw: "Linux dataplane is Iptables"}
	if len(result.Missing) != 1 || !slices.Equal(result.Missing[0].DeclaredBy, want.DeclaredBy) || result.Missing[0].Saw != want.Saw {
		t.Errorf("missing = %+v, want [%+v]", result.Missing, want)
	}
}

func TestCheckPassesWhenTheClusterHasWhatItDeclares(t *testing.T) {
	cluster := fakeCluster(t, operatorInstall(operatorv1.LinuxDataplaneIptables))

	result := Check(context.Background(), cluster, Declarations{platform.Xtables: {"cluster/dataplane/iptables.yaml"}})

	if result.Failed() {
		t.Errorf("expected pass, got:\n%s", result.Summary())
	}
}

func TestCheckReportsUndeclaredCapabilitiesWithoutFailing(t *testing.T) {
	cluster := fakeCluster(t, operatorInstall(operatorv1.LinuxDataplaneBPF))

	result := Check(context.Background(), cluster, Declarations{})

	if result.Failed() {
		t.Errorf("an undeclared capability failed the check:\n%s", result.Summary())
	}
	if !slices.Contains(result.Undeclared, platform.BPF) {
		t.Errorf("undeclared = %v, want it to include BPF", result.Undeclared)
	}
	if slices.Contains(result.Undeclared, platform.Xtables) {
		t.Errorf("undeclared = %v, but the cluster runs BPF, not xtables", result.Undeclared)
	}
}

func TestCheckLeavesInstallationCapabilitiesUncheckedWithoutAnInstallation(t *testing.T) {
	cluster := fakeCluster(t)

	result := Check(context.Background(), cluster, Declarations{platform.BPF: {"cluster/dataplane/bpf.yaml"}})

	if result.Failed() {
		t.Errorf("a manifest install failed a capability it can't check:\n%s", result.Summary())
	}
	if !slices.ContainsFunc(result.Unchecked, func(s Skip) bool { return s.Capability == platform.BPF }) {
		t.Errorf("unchecked = %+v, want it to include BPF", result.Unchecked)
	}
}

func TestCheckLeavesTheCloudUncheckedOnNodesWithoutAProviderID(t *testing.T) {
	cluster := fakeCluster(t, node("a", "aws:///us-west-2a/i-1"), node("b", ""))

	result := Check(context.Background(), cluster, Declarations{platform.AWS: {"cluster/cloud/aws.yaml"}})

	if result.Failed() {
		t.Errorf("a node with no cloud provider failed the AWS declaration:\n%s", result.Summary())
	}
	if !slices.ContainsFunc(result.Unchecked, func(s Skip) bool { return s.Capability == platform.AWS }) {
		t.Errorf("unchecked = %+v, want it to include AWS", result.Unchecked)
	}
}

func TestCheckFailsAnOperatorDeclarationWithoutAnInstallation(t *testing.T) {
	cluster := fakeCluster(t)

	result := Check(context.Background(), cluster, Declarations{platform.Operator: {"cluster/install/operator.yaml"}})

	if !result.Failed() {
		t.Errorf("expected failure, got:\n%s", result.Summary())
	}
}

func TestCheckFailsOnACapabilityNoSpecCanRequire(t *testing.T) {
	cluster := fakeCluster(t)

	result := Check(context.Background(), cluster, Declarations{"NoSuchThing": {"cluster/capability/typo.yaml"}})

	if !result.Failed() {
		t.Errorf("expected failure for an unknown capability, got:\n%s", result.Summary())
	}
}

func TestDeclarationsFromNamesEveryFileThatDeclaresACapability(t *testing.T) {
	dir := t.TempDir()
	bpf := writeConfig(t, dir, "cluster/dataplane/bpf.yaml", "kind: cluster\nprovides: [BPF, PolicyTiers]\n")
	dsr := writeConfig(t, dir, "cluster/capability/bpf-dsr.yaml", "kind: cluster\nprovides: [BPFDSR, BPF]\n")

	decls, err := DeclarationsFrom([]string{bpf, dsr})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := decls[platform.BPF]; !slices.Equal(got, []string{bpf, dsr}) {
		t.Errorf("BPF declared by %v, want both files", got)
	}
	if got := decls[platform.PolicyTiers]; !slices.Equal(got, []string{bpf}) {
		t.Errorf("PolicyTiers declared by %v, want only %s", got, bpf)
	}
}

func TestWriteJUnitTagsUndeclaredCapabilitiesAndFailsOnMissingOnes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "junit-capability.xml")
	result := &Result{
		Missing:    []Miss{{Capability: platform.BPF, DeclaredBy: []string{"cluster/dataplane/bpf.yaml"}, Saw: "Linux dataplane is Iptables"}},
		Undeclared: []platform.Capability{platform.BGP, platform.AWS},
	}

	if err := WriteJUnit(path, result, time.Second); err != nil {
		t.Fatalf("write: %v", err)
	}
	tc := readOneCase(t, path)

	if tc.Name != "capability check [Undeclared:BGP] [Undeclared:AWS]" {
		t.Errorf("case name = %q", tc.Name)
	}
	if tc.Failure == nil || !strings.Contains(tc.Failure.Message, "BPF") {
		t.Errorf("failure = %+v, want one naming BPF", tc.Failure)
	}
}

func TestWriteJUnitPassesACleanCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "junit-capability.xml")

	if err := WriteJUnit(path, &Result{}, time.Second); err != nil {
		t.Fatalf("write: %v", err)
	}
	tc := readOneCase(t, path)

	if tc.Name != "capability check" || tc.Failure != nil {
		t.Errorf("case = %+v, want a passing case with no tags", tc)
	}
}

func TestWriteJUnitFailsACheckThatCouldNotRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "junit-capability.xml")

	if err := WriteJUnit(path, CouldNotRun(os.ErrNotExist), time.Second); err != nil {
		t.Fatalf("write: %v", err)
	}
	if tc := readOneCase(t, path); tc.Failure == nil {
		t.Errorf("a check that never ran passed")
	}
}

// probeCase is one cluster state and what a probe should make of it.
type probeCase struct {
	name        string
	capability  platform.Capability
	objects     []ctrlclient.Object
	groups      []string
	wantPresent bool
}

func TestProbes(t *testing.T) {
	cases := []probeCase{
		{name: "calico-apiserver is aggregated", capability: platform.AggregatedAPI, objects: []ctrlclient.Object{calicoAPIService(true)}, wantPresent: true},
		{name: "CRD-served API isn't aggregated", capability: platform.AggregatedAPI, objects: []ctrlclient.Object{calicoAPIService(false)}},
		{name: "CRD-served API is V3CRDs", capability: platform.V3CRDs, objects: []ctrlclient.Object{calicoAPIService(false)}, wantPresent: true},
		{name: "calico-apiserver isn't V3CRDs", capability: platform.V3CRDs, objects: []ctrlclient.Object{calicoAPIService(true)}},
		{name: "unencapsulated pool", capability: platform.NoEncap, objects: []ctrlclient.Object{ipPool("a", "", v3.VXLANModeNever)}, wantPresent: true},
		{name: "IPIP pool", capability: platform.NoEncap, objects: []ctrlclient.Object{ipPool("a", v3.IPIPModeAlways, "")}},
		{name: "mesh with IPIP", capability: platform.BGPMesh, objects: []ctrlclient.Object{iptablesInstall(), ipPool("a", v3.IPIPModeAlways, "")}, wantPresent: true},
		{name: "mesh beside VXLAN", capability: platform.BGPMesh, objects: []ctrlclient.Object{iptablesInstall(), ipPool("a", "", v3.VXLANModeAlways)}},
		{name: "BIRD routing", capability: platform.BGPRouting, objects: []ctrlclient.Object{iptablesInstall(), felixConfig(felixDefaults)}, wantPresent: true},
		{name: "Felix routing", capability: platform.BGPRouting, objects: []ctrlclient.Object{iptablesInstall(), felixConfig(felixProgramsRoutes)}},
		{name: "BPF with DSR", capability: platform.BPFDSR, objects: []ctrlclient.Object{operatorInstall(operatorv1.LinuxDataplaneBPF), felixConfig(externalServiceMode("dsr"))}, wantPresent: true},
		{name: "BPF with tunnel", capability: platform.BPFDSR, objects: []ctrlclient.Object{operatorInstall(operatorv1.LinuxDataplaneBPF), felixConfig(externalServiceMode("Tunnel"))}},
		{name: "VPP has no tiers", capability: platform.PolicyTiers, objects: []ctrlclient.Object{operatorInstall(operatorv1.LinuxDataplaneVPP)}},
		{name: "BPF has tiers", capability: platform.PolicyTiers, objects: []ctrlclient.Object{operatorInstall(operatorv1.LinuxDataplaneBPF)}, wantPresent: true},
		{name: "WireGuard v6 only", capability: platform.WireGuard, objects: []ctrlclient.Object{felixConfig(wireGuardV6On)}, wantPresent: true},
		{name: "WireGuard off", capability: platform.WireGuard, objects: []ctrlclient.Object{felixConfig(felixDefaults)}},
		{name: "Goldmane available", capability: platform.Goldmane, objects: []ctrlclient.Object{goldmaneStatus(operatorv1.ConditionTrue)}, wantPresent: true},
		{name: "Goldmane degraded", capability: platform.Goldmane, objects: []ctrlclient.Object{goldmaneStatus(operatorv1.ConditionFalse)}},
		{name: "every node on AWS", capability: platform.AWS, objects: []ctrlclient.Object{node("a", "aws:///us-west-2a/i-1"), node("b", "aws:///us-west-2a/i-2")}, wantPresent: true},
		{name: "one node off AWS", capability: platform.AWS, objects: []ctrlclient.Object{node("a", "aws:///us-west-2a/i-1"), node("b", "kind://docker/kind/b")}},
		{name: "dual-stack nodes have IPv6", capability: platform.IPv6, objects: []ctrlclient.Object{nodeWithIPs("a", "10.0.0.1", "fd00::1")}, wantPresent: true},
		{name: "IPv4-only nodes lack IPv6", capability: platform.IPv6, objects: []ctrlclient.Object{nodeWithIPs("a", "10.0.0.1")}},
		{name: "IPv6-only nodes lack IPv4", capability: platform.IPv4, objects: []ctrlclient.Object{nodeWithIPs("a", "fd00::1")}},
		{name: "IPv4 on every node", capability: platform.IPv4, objects: []ctrlclient.Object{nodeWithIPs("a", "10.0.0.1"), nodeWithIPs("b", "10.0.0.2", "fd00::2")}, wantPresent: true},
		{name: "OpenShift served", capability: platform.OpenShift, groups: []string{"config.openshift.io"}, wantPresent: true},
		{name: "OpenShift not served", capability: platform.OpenShift, groups: []string{"apps"}},
		{name: "KubeVirt served", capability: platform.KubeVirt, groups: []string{"kubevirt.io"}, wantPresent: true},
		{name: "KubeVirt not served", capability: platform.KubeVirt, groups: []string{"apps"}},
		{name: "MockVirt simulates", capability: platform.MockVirt, objects: []ctrlclient.Object{kubeVirt(true)}, wantPresent: true},
		{name: "real KubeVirt isn't MockVirt", capability: platform.MockVirt, objects: []ctrlclient.Object{kubeVirt(false)}},
		{name: "real KubeVirt", capability: platform.RealKubeVirt, objects: []ctrlclient.Object{kubeVirt(false)}, wantPresent: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cluster := fakeCluster(t, tc.objects...)
			cluster.discovery = fakeDiscovery{groups: tc.groups}

			f, err := probes[tc.capability](context.Background(), cluster)
			if err != nil {
				t.Fatalf("probe error: %v", err)
			}
			if f.unchecked || f.present != tc.wantPresent {
				t.Errorf("%s = %+v, want present=%t", tc.capability, f, tc.wantPresent)
			}
		})
	}
}

func fakeCluster(t *testing.T, objects ...ctrlclient.Object) *Cluster {
	t.Helper()
	scheme, err := newScheme()
	if err != nil {
		t.Fatal(err)
	}
	return &Cluster{
		client:    fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build(),
		discovery: fakeDiscovery{},
	}
}

// fakeDiscovery serves the named API groups and no resources.
type fakeDiscovery struct {
	groups []string
}

func (d fakeDiscovery) ServerGroups() (*metav1.APIGroupList, error) {
	list := &metav1.APIGroupList{}
	for _, g := range d.groups {
		list.Groups = append(list.Groups, metav1.APIGroup{Name: g})
	}
	return list, nil
}

func (d fakeDiscovery) ServerResourcesForGroupVersion(string) (*metav1.APIResourceList, error) {
	return &metav1.APIResourceList{}, nil
}

// operatorInstall is an operator-managed Calico install with BGP on and the
// given dataplane, as the operator computes it.
func operatorInstall(dataplane operatorv1.LinuxDataplaneOption) *operatorv1.Installation {
	return &operatorv1.Installation{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Status: operatorv1.InstallationStatus{
			Computed: &operatorv1.InstallationSpec{
				CNI: &operatorv1.CNISpec{Type: operatorv1.PluginCalico, IPAM: &operatorv1.IPAMSpec{Type: operatorv1.IPAMPluginCalico}},
				CalicoNetwork: &operatorv1.CalicoNetworkSpec{
					BGP:            ptr.To(operatorv1.BGPEnabled),
					LinuxDataplane: ptr.To(dataplane),
				},
			},
		},
	}
}

func iptablesInstall() *operatorv1.Installation {
	return operatorInstall(operatorv1.LinuxDataplaneIptables)
}

func calicoAPIService(aggregated bool) *apiregistrationv1.APIService {
	svc := &apiregistrationv1.APIService{ObjectMeta: metav1.ObjectMeta{Name: calicoAPIServiceName}}
	if aggregated {
		svc.Spec.Service = &apiregistrationv1.ServiceReference{Namespace: "calico-system", Name: "calico-api"}
	}
	return svc
}

func ipPool(name string, ipip v3.IPIPMode, vxlan v3.VXLANMode) *v3.IPPool {
	return &v3.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       v3.IPPoolSpec{CIDR: "192.168.0.0/16", IPIPMode: ipip, VXLANMode: vxlan},
	}
}

// felixConfigEdit sets the fields a case cares about on the default config.
type felixConfigEdit func(fc *v3.FelixConfiguration)

func felixDefaults(*v3.FelixConfiguration) {}

func felixProgramsRoutes(fc *v3.FelixConfiguration) {
	fc.Spec.ProgramClusterRoutes = ptr.To(v3.Enabled)
}

func wireGuardV6On(fc *v3.FelixConfiguration) {
	fc.Spec.WireguardEnabledV6 = ptr.To(true)
}

func externalServiceMode(mode string) felixConfigEdit {
	return func(fc *v3.FelixConfiguration) {
		fc.Spec.BPFExternalServiceMode = mode
	}
}

func felixConfig(edit felixConfigEdit) *v3.FelixConfiguration {
	fc := &v3.FelixConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
	edit(fc)
	return fc
}

func goldmaneStatus(available operatorv1.ConditionStatus) *operatorv1.TigeraStatus {
	return &operatorv1.TigeraStatus{
		ObjectMeta: metav1.ObjectMeta{Name: "goldmane"},
		Status: operatorv1.TigeraStatusStatus{
			Conditions: []operatorv1.TigeraStatusCondition{{Type: operatorv1.ComponentAvailable, Status: available}},
		},
	}
}

func node(name, providerID string) *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: corev1.NodeSpec{ProviderID: providerID}}
}

func nodeWithIPs(name string, ips ...string) *corev1.Node {
	n := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}}
	for _, ip := range ips {
		n.Status.Addresses = append(n.Status.Addresses, corev1.NodeAddress{Type: corev1.NodeInternalIP, Address: ip})
	}
	return n
}

// kubeVirt is unstructured because the vendored KubeVirt types predate the
// simulation mode MockVirt sets.
func kubeVirt(simulated bool) *unstructured.Unstructured {
	kv := &unstructured.Unstructured{}
	kv.SetGroupVersionKind(schema.GroupVersionKind{Group: kubeVirtGroup, Version: "v1", Kind: "KubeVirt"})
	kv.SetNamespace("kubevirt")
	kv.SetName("kubevirt")
	kv.Object["spec"] = map[string]any{
		"configuration": map[string]any{
			"developerConfiguration": map[string]any{"simulationMode": simulated},
		},
	}
	return kv
}

func writeConfig(t *testing.T, dir, rel, content string) string {
	t.Helper()
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
	return path
}

func readOneCase(t *testing.T, path string) reporters.JUnitTestCase {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var suites reporters.JUnitTestSuites
	if err := xml.Unmarshal(data, &suites); err != nil {
		t.Fatalf("parse report: %v", err)
	}
	if len(suites.TestSuites) != 1 || len(suites.TestSuites[0].TestCases) != 1 {
		t.Fatalf("report holds %+v, want one suite with one case", suites)
	}
	return suites.TestSuites[0].TestCases[0]
}
