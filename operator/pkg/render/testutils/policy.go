// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.

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

package testutils

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/onsi/gomega"

	rtest "github.com/tigera/operator/pkg/render/common/test"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
)

// CalicoSystemScenario represents valid render cases for calico-system policies. Render components should test that their
// calico-system policies correctly adapt for each relevant potential case. Update if new scenarios arise.
type CalicoSystemScenario struct {
	ManagedCluster    bool
	ManagementCluster bool
	OpenShift         bool
	DPIEnabled        bool
}

type IPMode string

const (
	IPV4      IPMode = "IPV4"
	IPV6      IPMode = "IPV6"
	DualStack IPMode = "Dual-stack"
)

func GetCalicoSystemPolicyFromResources(name types.NamespacedName, resources []client.Object) *v3.NetworkPolicy {
	resource := rtest.GetResource(resources, name.Name, name.Namespace, "projectcalico.org", "v3", "NetworkPolicy")
	if resource == nil {
		return nil
	} else {
		return resource.(*v3.NetworkPolicy)
	}
}

func GetCalicoSystemGlobalPolicyFromResources(name string, resources []client.Object) *v3.GlobalNetworkPolicy {
	resource := rtest.GetGlobalResource(resources, name, "projectcalico.org", "v3", "GlobalNetworkPolicy")
	if resource == nil {
		return nil
	} else {
		return resource.(*v3.GlobalNetworkPolicy)
	}
}

func GetExpectedPolicyFromFile(name string) *v3.NetworkPolicy {
	return GetExpectedPolicyFromFileWithReplacements(name, nil)
}

func GetExpectedPolicyFromFileWithReplacements(name string, replacements map[string]string) *v3.NetworkPolicy {
	jsonFile, err := os.Open(name)
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
	defer func() { _ = jsonFile.Close() }()

	byteValue, err := io.ReadAll(jsonFile)
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

	content := string(byteValue)
	for k, v := range replacements {
		content = strings.ReplaceAll(content, fmt.Sprintf("<%s>", k), v)
	}

	var policy v3.NetworkPolicy
	err = json.Unmarshal([]byte(content), &policy)
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

	return &policy
}

func GetExpectedGlobalPolicyFromFile(name string) *v3.GlobalNetworkPolicy {
	jsonFile, err := os.Open(name)
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
	defer func() { _ = jsonFile.Close() }()

	byteValue, err := io.ReadAll(jsonFile)
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

	var policy v3.GlobalNetworkPolicy
	err = json.Unmarshal(byteValue, &policy)
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

	return &policy
}

// SelectPolicyByClusterTypeAndProvider selects a variant of a policy that varies depending on cluster and provider type.
func SelectPolicyByClusterTypeAndProvider(scenario CalicoSystemScenario, policies map[string]*v3.NetworkPolicy) *v3.NetworkPolicy {
	clusterType := "unmanaged"
	if scenario.ManagementCluster {
		clusterType = "management"
	} else if scenario.ManagedCluster {
		clusterType = "managed"
	} else if _, ok := policies["standalone"]; ok {
		clusterType = "standalone"
	}

	key := clusterType
	if scenario.OpenShift {
		key += "-openshift"
	}

	return policies[key]
}

// SelectPolicyByProvider simply selects a variant of a policy that varies depending on provider type only.
func SelectPolicyByProvider(scenario CalicoSystemScenario, noProviderPolicy *v3.NetworkPolicy, openshiftProviderPolicy *v3.NetworkPolicy) *v3.NetworkPolicy {
	if scenario.OpenShift {
		return openshiftProviderPolicy
	} else {
		return noProviderPolicy
	}
}
