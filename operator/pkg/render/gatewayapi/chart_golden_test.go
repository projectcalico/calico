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

package gatewayapi

import (
	"path/filepath"
	"reflect"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/operator/pkg/render/common/helm/helmtest"
)

var _ = It("renders the Envoy Gateway chart as in the golden file", func() {
	resources, err := renderChart(testScheme())
	Expect(err).NotTo(HaveOccurred())

	out, err := helmtest.ToYAML(chartObjects(resources))
	Expect(err).NotTo(HaveOccurred())
	Expect(helmtest.CompareGolden(filepath.Join("testdata", "envoy-gateway.golden.yaml"), out)).To(Succeed())
})

// chartObjects lists every gatewayAPIResources field. The field count check
// fails when a field is added, so it cannot be left out of the golden file.
func chartObjects(r *gatewayAPIResources) []client.Object {
	// envoyGatewayConfig is parsed from envoyGatewayConfigMap, which is pinned.
	objs := []client.Object{
		r.controllerServiceAccount, r.envoyGatewayConfigMap,
		r.role, r.roleBinding, r.leaderElectionRole, r.leaderElectionRoleBinding,
		r.controllerService, r.controllerDeployment,
		r.certgenServiceAccount, r.certgenRole, r.certgenRoleBinding, r.certgenJob,
	}
	const singleFields = 13
	objs = appendAll(objs, r.k8sCRDs)
	objs = appendAll(objs, r.envoyCRDs)
	objs = appendAll(objs, r.clusterRoles)
	objs = appendAll(objs, r.clusterRoleBindings)
	objs = appendAll(objs, r.mutatingWebhookConfigurations)
	objs = appendAll(objs, r.validatingAdmissionPolicies)
	objs = appendAll(objs, r.validatingAdmissionPolicyBindings)
	const sliceFields = 7
	ExpectWithOffset(1, reflect.TypeOf(*r).NumField()).To(Equal(singleFields+sliceFields),
		"gatewayAPIResources has a new field: add it to chartObjects")

	var present []client.Object
	for _, o := range objs {
		if o != nil && !reflect.ValueOf(o).IsNil() {
			present = append(present, o)
		}
	}
	return present
}

func appendAll[T client.Object](objs []client.Object, items []T) []client.Object {
	for _, o := range items {
		objs = append(objs, o)
	}
	return objs
}
