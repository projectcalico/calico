// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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

package helm_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// This file holds all of the functions for validating
// expected values on the Typha deployment.

var _ = Describe("Typha Helm Chart", func() {
	Context("With typha enabled with kubernetes datastore", func() {
		values := HelmValues{
			Datastore: "kubernetes",
			Typha: TyphaSettings{
				Enabled: true,
			},
		}

		resources, err := render(values)

		It("Renders the helm resources without issue", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		It("Creates the calico-typha deployment", func() {
			Expect(resources["Deployment,kube-system,calico-typha"]).NotTo(BeNil())
		})

		It("Creates the calico-typha service", func() {
			Expect(resources["Service,kube-system,calico-typha"]).NotTo(BeNil())
		})

		It("Creates the calico-typha pod disruption budget", func() {
			Expect(resources["PodDisruptionBudget,kube-system,calico-typha"]).NotTo(BeNil())
		})
	})

	Context("With typha disabled with kubernetes datastore", func() {
		values := HelmValues{
			Datastore: "kubernetes",
			Typha: TyphaSettings{
				Enabled: false,
			},
		}

		resources, err := render(values)

		It("Renders the helm resources without issue", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		It("Does not create the calico-typha deployment", func() {
			Expect(resources["Deployment,kube-system,calico-typha"]).To(BeNil())
		})

		It("Does not creates the calico-typha service", func() {
			Expect(resources["Service,kube-system,calico-typha"]).To(BeNil())
		})

		It("Does not create the calico-typha pod disruption budget", func() {
			Expect(resources["PodDisruptionBudget,kube-system,calico-typha"]).To(BeNil())
		})

	})

	Context("With typha enabled with etcd datastore", func() {
		values := HelmValues{
			Datastore: "etcd",
			Typha: TyphaSettings{
				Enabled: true,
			},
			Etcd: EtcdSettings{
				Endpoints: "http://127.0.0.1:2379",
			},
		}

		resources, err := render(values)

		It("Renders the helm resources without issue", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		It("Does not create the calico-typha deployment", func() {
			Expect(resources["Deployment,kube-system,calico-typha"]).To(BeNil())
		})

		It("Does not creates the calico-typha service", func() {
			Expect(resources["Service,kube-system,calico-typha"]).To(BeNil())
		})

		It("Does not create the calico-typha pod disruption budget", func() {
			Expect(resources["PodDisruptionBudget,kube-system,calico-typha"]).To(BeNil())
		})

	})

	Context("With typha disabled with etcd datastore", func() {
		values := HelmValues{
			Datastore: "etcd",
			Typha: TyphaSettings{
				Enabled: true,
			},
			Etcd: EtcdSettings{
				Endpoints: "http://127.0.0.1:2379",
			},
		}

		resources, err := render(values)

		It("Renders the helm resources without issue", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		It("Does not create the calico-typha deployment", func() {
			Expect(resources["Deployment,kube-system,calico-typha"]).To(BeNil())
		})

		It("Does not creates the calico-typha service", func() {
			Expect(resources["Service,kube-system,calico-typha"]).To(BeNil())
		})

		It("Does not create the calico-typha pod disruption budget", func() {
			Expect(resources["PodDisruptionBudget,kube-system,calico-typha"]).To(BeNil())
		})

	})
})
