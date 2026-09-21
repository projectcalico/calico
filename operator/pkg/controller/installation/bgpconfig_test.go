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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/utils/ptr"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/controller/managedfields"
)

var _ = Describe("BGPConfiguration declarations", func() {
	var r ReconcileInstallation

	install := func(mode *operatorv1.ClusterRoutingMode) *operatorv1.Installation {
		return &operatorv1.Installation{Spec: operatorv1.InstallationSpec{
			CNI:           &operatorv1.CNISpec{Type: operatorv1.PluginCalico},
			CalicoNetwork: &operatorv1.CalicoNetworkSpec{ClusterRoutingMode: mode},
		}}
	}

	It("declares the BIRD value complementary to the one Felix gets", func() {
		d, err := r.declareBGPConfiguration(install(ptr.To(operatorv1.ClusterRoutingModeFelix)))(&v3.BGPConfiguration{})
		Expect(err).NotTo(HaveOccurred())
		Expect(d.Manager).To(Equal(installationFieldManager))
		Expect(d.Policies["spec.programClusterRoutes"]).To(Equal(managedfields.ConflictOverride))
		Expect(d.Owned.(*v3.BGPConfiguration).Spec.ProgramClusterRoutes).To(Equal(ptr.To("Disabled")))
	})

	It("governs the field whether or not the Installation asks for a mode", func() {
		// Declared with no value, which is what clears whatever the operator wrote there.
		d, err := r.declareBGPConfiguration(install(nil))(&v3.BGPConfiguration{})
		Expect(err).NotTo(HaveOccurred())
		Expect(d.Policies).To(HaveKey("spec.programClusterRoutes"))
		Expect(d.Owned.(*v3.BGPConfiguration).Spec.ProgramClusterRoutes).To(BeNil())
	})
})
