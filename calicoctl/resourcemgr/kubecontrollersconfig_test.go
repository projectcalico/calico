// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

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

package resourcemgr_test

import (
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
)

var _ = Describe("KubeControllersConfig tests", func() {

	It("Should return full spec as is", func() {
		text := `apiVersion: projectcalico.org/v3
kind: KubeControllersConfiguration
metadata:
  name: default
spec:
  logSeverityScreen: Info
  healthChecks: Enabled
  etcdv3CompactionPeriod: 10m30s
  controllers:
    node:
      reconcilerPeriod: 1m
      syncLabels: Enabled
      hostEndpoint:
        autoCreate: Disabled
    policy:
      reconcilerPeriod: 2m
    workloadEndpoint:
      reconcilerPeriod: 3m
    serviceAccount:
      reconcilerPeriod: 4m
    namespace:
      reconcilerPeriod: 5m
`
		resources, err := createResources(text)
		Expect(err).NotTo(HaveOccurred())
		Expect(resources).To(HaveLen(1))
		kcc := resources[0].(*api.KubeControllersConfiguration)
		Expect(kcc.Name).To(Equal("default"))
		Expect(kcc.Spec.LogSeverityScreen).To(Equal("Info"))
		Expect(kcc.Spec.HealthChecks).To(Equal(api.Enabled))
		Expect(kcc.Spec.EtcdV3CompactionPeriod).To(Equal(&v1.Duration{Duration: (time.Minute * 10) + (time.Second * 30)}))
		Expect(kcc.Spec.Controllers.Node).To(Equal(&api.NodeControllerConfig{
			ReconcilerPeriod: &v1.Duration{Duration: time.Minute},
			SyncLabels:       api.Enabled,
			HostEndpoint:     &api.AutoHostEndpointConfig{AutoCreate: api.Disabled},
		}))
		Expect(kcc.Spec.Controllers.Policy).
			To(Equal(&api.PolicyControllerConfig{ReconcilerPeriod: &v1.Duration{Duration: time.Minute * 2}}))
		Expect(kcc.Spec.Controllers.WorkloadEndpoint).
			To(Equal(&api.WorkloadEndpointControllerConfig{ReconcilerPeriod: &v1.Duration{Duration: time.Minute * 3}}))
		Expect(kcc.Spec.Controllers.ServiceAccount).
			To(Equal(&api.ServiceAccountControllerConfig{ReconcilerPeriod: &v1.Duration{Duration: time.Minute * 4}}))
		Expect(kcc.Spec.Controllers.Namespace).
			To(Equal(&api.NamespaceControllerConfig{ReconcilerPeriod: &v1.Duration{Duration: time.Minute * 5}}))

		// Status
		Expect(kcc.Status.EnvironmentVars).To(BeNil())
		Expect(kcc.Status.RunningConfig.Controllers.Node).To(BeNil())
		Expect(kcc.Status.RunningConfig.Controllers.Policy).To(BeNil())
		Expect(kcc.Status.RunningConfig.Controllers.WorkloadEndpoint).To(BeNil())
		Expect(kcc.Status.RunningConfig.Controllers.ServiceAccount).To(BeNil())
		Expect(kcc.Status.RunningConfig.Controllers.Namespace).To(BeNil())
		Expect(kcc.Status.RunningConfig.LogSeverityScreen).To(Equal(""))
		Expect(kcc.Status.RunningConfig.HealthChecks).To(Equal(""))
		Expect(kcc.Status.RunningConfig.EtcdV3CompactionPeriod).To(BeNil())
	})

})
