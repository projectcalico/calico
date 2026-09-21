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

package installation

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/controller/managedfields"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
)

// ownedFelixConfig is the object a FelixConfiguration declaration sets its fields on.
func ownedFelixConfig(d *managedfields.Declaration) *v3.FelixConfiguration {
	return d.Owned.(*v3.FelixConfiguration)
}

var _ = Describe("FelixConfiguration declarations", func() {
	var r ReconcileInstallation

	nftables := operatorv1.LinuxDataplaneNftables

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(operatorv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
		r = ReconcileInstallation{
			ext:    coreExtensions.Installation(),
			client: ctrlrfake.DefaultFakeClientBuilder(scheme).Build(),
		}
	})

	install := func() *operatorv1.Installation {
		return &operatorv1.Installation{Spec: operatorv1.InstallationSpec{
			CNI:           &operatorv1.CNISpec{Type: operatorv1.PluginCalico},
			CalicoNetwork: &operatorv1.CalicoNetworkSpec{LinuxDataplane: &nftables},
		}}
	}

	declaredPaths := func(i *operatorv1.Installation, current *v3.FelixConfiguration) []string {
		d, err := r.declareFelixConfiguration(context.Background(), i, false)(current)
		Expect(err).NotTo(HaveOccurred())
		paths := []string{}
		for path := range d.Policies {
			paths = append(paths, path)
		}
		return paths
	}

	governed := []string{
		"spec.routeTableRange",
		"spec.healthPort",
		"spec.vxlanVNI",
		"spec.vxlanPort",
		"spec.bpfHostConntrackBypass",
		"spec.bpfKubeProxyHealthzPort",
		"spec.nftablesMode",
		"spec.programClusterRoutes",
	}

	It("declares the same fields no matter what the current object holds", func() {
		Expect(declaredPaths(install(), &v3.FelixConfiguration{})).To(ConsistOf(governed))

		// Every field the operator defaults is already set, by the operator or by anyone else.
		populated := declaredPaths(install(), &v3.FelixConfiguration{Spec: v3.FelixConfigurationSpec{
			HealthPort:   ptr.To(1234),
			VXLANVNI:     ptr.To(9999),
			VXLANPort:    ptr.To(1111),
			NFTablesMode: ptr.To(v3.NFTablesModeDisabled),
		}})
		Expect(populated).To(ConsistOf(governed))
	})

	It("declares the same fields no matter what the Installation asks for", func() {
		bpf := operatorv1.LinuxDataplaneBPF
		specs := []struct {
			name    string
			install *operatorv1.Installation
		}{
			{name: "the default install", install: install()},
			{name: "iptables on AWS", install: &operatorv1.Installation{Spec: operatorv1.InstallationSpec{
				CNI:                &operatorv1.CNISpec{Type: operatorv1.PluginAmazonVPC},
				KubernetesProvider: operatorv1.ProviderEKS,
			}}},
			{name: "eBPF on MKE", install: &operatorv1.Installation{Spec: operatorv1.InstallationSpec{
				CNI:                &operatorv1.CNISpec{Type: operatorv1.PluginCalico},
				KubernetesProvider: operatorv1.ProviderDockerEE,
				CalicoNetwork:      &operatorv1.CalicoNetworkSpec{LinuxDataplane: &bpf},
			}}},
			{name: "OpenShift with cluster routing set", install: &operatorv1.Installation{Spec: operatorv1.InstallationSpec{
				CNI:                &operatorv1.CNISpec{Type: operatorv1.PluginCalico},
				KubernetesProvider: operatorv1.ProviderOpenShift,
				CalicoNetwork: &operatorv1.CalicoNetworkSpec{
					LinuxDataplane:     &nftables,
					ClusterRoutingMode: ptr.To(operatorv1.ClusterRoutingModeFelix),
				},
			}}},
		}
		for _, spec := range specs {
			Expect(declaredPaths(spec.install, &v3.FelixConfiguration{})).To(ConsistOf(governed), spec.name)
		}
	})

	It("clears a field the Installation stops asking for", func() {
		i := install()
		i.Spec.CalicoNetwork.ClusterRoutingMode = ptr.To(operatorv1.ClusterRoutingModeFelix)
		d, err := r.declareFelixConfiguration(context.Background(), i, false)(&v3.FelixConfiguration{})
		Expect(err).NotTo(HaveOccurred())
		Expect(ownedFelixConfig(d).Spec.ProgramClusterRoutes).NotTo(BeNil())

		// Declared with no value, which is what clears whatever the operator wrote there.
		d, err = r.declareFelixConfiguration(context.Background(), install(), false)(&v3.FelixConfiguration{})
		Expect(err).NotTo(HaveOccurred())
		Expect(ownedFelixConfig(d).Spec.ProgramClusterRoutes).To(BeNil())
		Expect(d.Policies).To(HaveKey("spec.programClusterRoutes"))
	})

	It("declares the values it wants, not the values already there", func() {
		current := &v3.FelixConfiguration{Spec: v3.FelixConfigurationSpec{HealthPort: ptr.To(1234)}}
		d, err := r.declareFelixConfiguration(context.Background(), install(), false)(current)
		Expect(err).NotTo(HaveOccurred())
		Expect(ownedFelixConfig(d).Spec.HealthPort).To(Equal(ptr.To(9099)))
		Expect(d.Policies["spec.healthPort"]).To(Equal(managedfields.ConflictDefer))
	})

	It("defers to a user on defaults and overrides them on modes it owns outright", func() {
		i := install()
		i.Spec.CalicoNetwork.ClusterRoutingMode = ptr.To(operatorv1.ClusterRoutingModeFelix)
		d, err := r.declareFelixConfiguration(context.Background(), i, false)(&v3.FelixConfiguration{})
		Expect(err).NotTo(HaveOccurred())
		Expect(d.Manager).To(Equal(installationFieldManager))
		Expect(d.Policies["spec.programClusterRoutes"]).To(Equal(managedfields.ConflictOverride))
		Expect(ownedFelixConfig(d).Spec.ProgramClusterRoutes).To(Equal(ptr.To("Enabled")))
	})

	It("declares nothing while calico-node still serves nodes out of kube-system", func() {
		bpf := operatorv1.LinuxDataplaneBPF
		i := install()
		i.Spec.CalicoNetwork.LinuxDataplane = &bpf

		d, err := r.declareBPFEnabled(context.Background(), i, true)(&v3.FelixConfiguration{})
		Expect(err).NotTo(HaveOccurred())
		Expect(d).To(BeNil())

		d, err = r.declareBPFEnabled(context.Background(), i, false)(&v3.FelixConfiguration{})
		Expect(err).NotTo(HaveOccurred())
		Expect(ownedFelixConfig(d).Spec.BPFEnabled).To(Equal(ptr.To(true)))
	})

	It("declares bpfEnabled under its own manager, refusing to fight over it", func() {
		d, err := r.declareBPFEnabled(context.Background(), install(), false)(&v3.FelixConfiguration{})
		Expect(err).NotTo(HaveOccurred())
		Expect(d.Manager).To(Equal(bpfFieldManager))
		Expect(d.Policies).To(HaveLen(1))
		Expect(d.Policies["spec.bpfEnabled"]).To(Equal(managedfields.ConflictError))
		Expect(ownedFelixConfig(d).Spec.BPFEnabled).To(Equal(ptr.To(false)))
	})
})
