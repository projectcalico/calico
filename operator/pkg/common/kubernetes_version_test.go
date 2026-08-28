// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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

package common

import (
	"fmt"
	"strconv"

	"k8s.io/apimachinery/pkg/version"
	discoveryFake "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Test get Kubernetes version", func() {
	var clientset kubernetes.Interface

	BeforeEach(func() {
		clientset = fake.NewClientset()
	})

	It("should return expected major and minor version when both version numbers are valid integers", func() {
		expectedMajor := 3
		expectedMinor := 22
		clientset.Discovery().(*discoveryFake.FakeDiscovery).FakedServerVersion = &version.Info{
			Major: strconv.Itoa(expectedMajor),
			Minor: strconv.Itoa(expectedMinor),
		}

		version, err := GetKubernetesVersion(clientset)
		Expect(err).NotTo(HaveOccurred())
		Expect(version.Major).To(Equal(expectedMajor))
		Expect(version.Minor).To(Equal(expectedMinor))
	})

	It("should return error when major version is invalid", func() {
		invalidMajor := "invalid_major_version"
		clientset.Discovery().(*discoveryFake.FakeDiscovery).FakedServerVersion = &version.Info{
			Major: invalidMajor,
			Minor: "19",
		}

		v, err := GetKubernetesVersion(clientset)
		Expect(v).To(BeNil())
		Expect(err).To(HaveOccurred())
		Expect(err).To(Equal(fmt.Errorf("failed to parse k8s major version: %s", invalidMajor)))
	})

	It("should return error when minor version is invalid", func() {
		invalidMinor := "invalid_minor_version"
		clientset.Discovery().(*discoveryFake.FakeDiscovery).FakedServerVersion = &version.Info{
			Major: "1",
			Minor: invalidMinor,
		}

		v, err := GetKubernetesVersion(clientset)
		Expect(v).To(BeNil())
		Expect(err).To(HaveOccurred())
		Expect(err).To(Equal(fmt.Errorf("failed to parse k8s minor version: %s", invalidMinor)))
	})
})
