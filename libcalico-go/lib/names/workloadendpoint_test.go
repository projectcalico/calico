// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package names_test

import (
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
)

var _ = DescribeTable("WorkloadEndpoint name construction, fully qualified names",
	func(ids names.WorkloadEndpointIdentifiers, expectedName string, expectedErroredField string) {
		name, err := ids.CalculateWorkloadEndpointName(false)
		if len(expectedErroredField) != 0 {
			Expect(name).To(Equal(""))
			Expect(err).To(HaveOccurred())
			Expect(err.(cerrors.ErrorValidation).ErroredFields).To(HaveLen(1))
			Expect(err.(cerrors.ErrorValidation).ErroredFields[0].Name).To(Equal(expectedErroredField))
		} else {
			Expect(name).To(Equal(expectedName))
		}
	},
	Entry("Valid k8s endpoint", names.WorkloadEndpointIdentifiers{
		Node:         "node-1",
		Orchestrator: "k8s",
		Pod:          "pod-name",
		Endpoint:     "eth0",
	}, "node--1-k8s-pod--name-eth0", ""),
	Entry("Valid CNI (non-k8s) endpoint", names.WorkloadEndpointIdentifiers{
		Node:         "node-1",
		Orchestrator: "cni",
		ContainerID:  "abcdefa0123456",
		Endpoint:     "eth0",
	}, "node--1-cni-abcdefa0123456-eth0", ""),
	Entry("Valid libnetwork endpoint", names.WorkloadEndpointIdentifiers{
		Node:         "node-1",
		Orchestrator: "libnetwork",
		Endpoint:     "abcdefgh",
	}, "node--1-libnetwork-libnetwork-abcdefgh", ""),
	Entry("Valid unknown orchestrator endpoint", names.WorkloadEndpointIdentifiers{
		Node:         "node-1",
		Orchestrator: "foo",
		Workload:     "foo-foo",
		Endpoint:     "abcdefgh",
	}, "node--1-foo-foo--foo-abcdefgh", ""),
	Entry("Missing orchestrator and workload but other unknown orchestrator fields are present", names.WorkloadEndpointIdentifiers{
		Node:     "node-1",
		Pod:      "pod-name",
		Endpoint: "eth0",
	}, "", "orchestrator"),
	Entry("Missing k8s Pod", names.WorkloadEndpointIdentifiers{
		Node:         "node-1",
		Orchestrator: "k8s",
		Endpoint:     "eth0",
	}, "", "pod"),
	Entry("CNI container ID starts with a -", names.WorkloadEndpointIdentifiers{
		Node:         "node-1",
		Orchestrator: "cni",
		ContainerID:  "-abcdefa0123456",
		Endpoint:     "eth0",
	}, "", "containerID"),
	Entry("Unknown orchestrator workload ends with a -", names.WorkloadEndpointIdentifiers{
		Node:         "node-1",
		Orchestrator: "foo",
		Workload:     "foo-foo-",
		Endpoint:     "abcdefgh",
	}, "", "workload"),
)

var _ = DescribeTable("WorkloadEndpoint name construction, name prefix",
	func(ids names.WorkloadEndpointIdentifiers, expectedName string, expectedErroredField string) {
		name, err := ids.CalculateWorkloadEndpointName(true)
		if len(expectedErroredField) != 0 {
			Expect(name).To(Equal(""))
			Expect(err).To(HaveOccurred())
			Expect(err.(cerrors.ErrorValidation).ErroredFields).To(HaveLen(1))
			Expect(err.(cerrors.ErrorValidation).ErroredFields[0].Name).To(Equal(expectedErroredField))
		} else {
			Expect(name).To(Equal(expectedName))
		}
	},
	Entry("Valid k8s endpoint", names.WorkloadEndpointIdentifiers{
		Node:         "node-1",
		Orchestrator: "k8s",
		Pod:          "pod-name",
		Endpoint:     "eth0",
	}, "node--1-k8s-pod--name-eth0", ""),
	Entry("Missing  workload but other unknown orchestrator fields are present", names.WorkloadEndpointIdentifiers{
		Node:         "node-1",
		Orchestrator: "foo",
		Pod:          "pod-name",
		Endpoint:     "eth0",
	}, "node--1-foo-", ""),
	Entry("Missing k8s Pod", names.WorkloadEndpointIdentifiers{
		Node:         "node-1",
		Orchestrator: "k8s",
		Endpoint:     "eth0",
	}, "node--1-k8s-", ""),
	Entry("CNI container ID starts with a -", names.WorkloadEndpointIdentifiers{
		Node:         "node-1",
		Orchestrator: "cni",
		ContainerID:  "-abcdefa0123456",
		Endpoint:     "eth0",
	}, "", "containerID"),
	Entry("Unknown orchestrator, workload ends with a -", names.WorkloadEndpointIdentifiers{
		Node:         "node-1",
		Orchestrator: "foo",
		Workload:     "foo-foo-",
		Endpoint:     "abcdefgh",
	}, "", "workload"),
	Entry("Node is missing", names.WorkloadEndpointIdentifiers{
		Orchestrator: "k8s",
		Pod:          "pod-name",
		Endpoint:     "eth0",
	}, "", "node"),
	Entry("Orchestrator is missing", names.WorkloadEndpointIdentifiers{
		Node:     "node-1",
		Pod:      "pod-name",
		Endpoint: "eth0",
	}, "node--1-", ""),
)

var _ = DescribeTable("WorkloadEndpoint name matching",
	func(ids names.WorkloadEndpointIdentifiers, name string, expectValid bool, expectedErroredField string) {
		valid, err := ids.NameMatches(name)
		if len(expectedErroredField) != 0 {
			Expect(valid).To(BeFalse())
			Expect(err).To(HaveOccurred())
			Expect(err.(cerrors.ErrorValidation).ErroredFields).To(HaveLen(1))
			Expect(err.(cerrors.ErrorValidation).ErroredFields[0].Name).To(Equal(expectedErroredField))
		} else {
			Expect(valid).To(Equal(expectValid))
		}
	},
	Entry("Node is missing", names.WorkloadEndpointIdentifiers{
		Orchestrator: "k8s",
		Pod:          "pod-name",
		Endpoint:     "eth0",
	}, "", false, "node"),
	Entry("Orchestrator is missing", names.WorkloadEndpointIdentifiers{
		Node:     "node-1",
		Pod:      "pod-name",
		Endpoint: "eth0",
	}, "", false, ""),
	Entry("Valid k8s endpoint and matching name", names.WorkloadEndpointIdentifiers{
		Node:         "node-1",
		Orchestrator: "k8s",
		Pod:          "pod-name",
		Endpoint:     "eth0",
	}, "node--1-k8s-pod--name-eth0", true, ""),
	Entry("Fully qualified k8s endpoint, non-matching Endpoint", names.WorkloadEndpointIdentifiers{
		Node:         "node-1",
		Orchestrator: "k8s",
		Pod:          "pod-name",
		Endpoint:     "eth0",
	}, "node--1-k8s-pod--name-eth", false, ""),
	Entry("CNI endpoint ids missing container ID but name matches remaining ids", names.WorkloadEndpointIdentifiers{
		Node:         "node-1",
		Orchestrator: "cni",
		Endpoint:     "eth0",
	}, "node--1-cni-orchestratorid-eth0", true, ""),
	Entry("Fully qualified CNI endpoint and matching name", names.WorkloadEndpointIdentifiers{
		Node:         "node-1",
		Orchestrator: "cni",
		ContainerID:  "abcde",
		Endpoint:     "eth0",
	}, "node--1-cni-abcde-eth0", true, ""),
	Entry("Fully qualified CNI endpoint and non-matching container", names.WorkloadEndpointIdentifiers{
		Node:         "node-1",
		Orchestrator: "cni",
		ContainerID:  "abcde",
		Endpoint:     "eth0",
	}, "node--1-cni-abcdef-eth0", false, ""),
	Entry("Too few name segments", names.WorkloadEndpointIdentifiers{
		Node:         "node-1",
		Orchestrator: "k8s",
		Endpoint:     "eth0",
	}, "node--1-k8s-", false, ""),
	Entry("Too many name segments", names.WorkloadEndpointIdentifiers{
		Node:         "node-1",
		Orchestrator: "k8s",
		Pod:          "pod",
		Endpoint:     "eth0",
	}, "node--1-k8s-pod-eth0-extra", false, ""),
)

var _ = DescribeTable("WorkloadEndpoint name parsing",
	func(name string, expectError bool, expectedWeid names.WorkloadEndpointIdentifiers) {
		weid, err := names.ParseWorkloadEndpointName(name)
		if expectError {
			Expect(err).To(HaveOccurred())
		} else {
			Expect(err).NotTo(HaveOccurred())
			Expect(weid).To(Equal(expectedWeid))
		}
	},
	Entry("Empty string", "", true, names.WorkloadEndpointIdentifiers{}),
	Entry("Fully populated k8s wep name", "node-k8s-pod-eth0", false, names.WorkloadEndpointIdentifiers{
		Node:         "node",
		Orchestrator: "k8s",
		Pod:          "pod",
		Endpoint:     "eth0",
	}),
	Entry("K8s prefix match with only node", "node-", false, names.WorkloadEndpointIdentifiers{
		Node: "node",
	}),
	Entry("K8s prefix match with node and pod", "node-k8s-pod--name-", false, names.WorkloadEndpointIdentifiers{
		Node:         "node",
		Orchestrator: "k8s",
		Pod:          "pod-name",
	}),
	Entry("Fully populated cni", "node-cni-xyz-eth0", false, names.WorkloadEndpointIdentifiers{
		Node:         "node",
		Orchestrator: "cni",
		ContainerID:  "xyz",
		Endpoint:     "eth0",
	}),
	Entry("Fully populated libnetwork", "node-libnetwork-libnetwork-eth0", false, names.WorkloadEndpointIdentifiers{
		Node:         "node",
		Orchestrator: "libnetwork",
		Endpoint:     "eth0",
	}),
	Entry("Fully populated other orchestrators", "node-foo--orch-workload-eth0", false, names.WorkloadEndpointIdentifiers{
		Node:         "node",
		Orchestrator: "foo-orch",
		Workload:     "workload",
		Endpoint:     "eth0",
	}),
)
