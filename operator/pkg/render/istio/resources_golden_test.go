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

package istio

import (
	"path/filepath"

	netattachv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiextv1 "k8s.io/apiextensions-api/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/render/common/helm/helmtest"
)

var _ = DescribeTable("Istio chart rendering matches the golden files",
	func(provider operatorv1.Provider, golden string) {
		s := runtime.NewScheme()
		Expect(scheme.AddToScheme(s)).To(Succeed())
		Expect(apiextv1.AddToScheme(s)).To(Succeed())
		Expect(netattachv1.AddToScheme(s)).To(Succeed())

		crds, _, err := Istio(&Configuration{
			Installation:   &operatorv1.InstallationSpec{KubernetesProvider: provider},
			IstioNamespace: IstioNamespace,
			Scheme:         s,
			ClusterID:      "golden-cluster",
		})
		Expect(err).NotTo(HaveOccurred())

		r := crds.resources
		var objs []client.Object
		for _, group := range [][]client.Object{r.CRDs, r.Base, r.Istiod, r.CNI, r.ZTunnel} {
			objs = append(objs, group...)
		}
		out, err := helmtest.ToYAML(objs)
		Expect(err).NotTo(HaveOccurred())
		Expect(helmtest.CompareGolden(filepath.Join("testdata", golden), out)).To(Succeed())
	},
	Entry("default platform", operatorv1.ProviderNone, "istio-default.golden.yaml"),
	Entry("GKE", operatorv1.ProviderGKE, "istio-gke.golden.yaml"),
	Entry("OpenShift", operatorv1.ProviderOpenShift, "istio-openshift.golden.yaml"),
)
