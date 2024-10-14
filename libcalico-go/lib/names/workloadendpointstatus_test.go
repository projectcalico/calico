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
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/felix/proto"
	v3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
)

var _ = DescribeTable("WorkloadEndpointKey to endpoint-status filename",
	func(k *model.WorkloadEndpointKey, expectedStr string) {
		genStr := names.WorkloadEndpointKeyToStatusFilename(k)
		Expect(genStr).To(Equal(expectedStr))
	},
	Entry("Valid workload endpoint key", &model.WorkloadEndpointKey{Hostname: "cluster-node-0", OrchestratorID: "k8s", WorkloadID: "default/testpod1", EndpointID: "eth0"}, "k8s default%2Ftestpod1 eth0"),
	Entry("Valid slash-filled key", &model.WorkloadEndpointKey{Hostname: "cl///uster-node-0", OrchestratorID: "k8/s", WorkloadID: "defaul/t/testp/od1", EndpointID: "eth/0"}, "k8%2Fs defaul%2Ft%2Ftestp%2Fod1 eth%2F0"),
	Entry("Valid space-filled key", &model.WorkloadEndpointKey{Hostname: "cluster-node-0", OrchestratorID: "k8s", WorkloadID: "default/t est pod1", EndpointID: "eth0"}, "k8s default%2Ft%20est%20pod1 eth0"),

	Entry("Nil key", nil, ""),
)

var _ = DescribeTable("WorkloadEndpointID to model.WorkloadEndpointKey",
	func(wepID *proto.WorkloadEndpointID, hostname string, expectedKey *model.WorkloadEndpointKey) {
		genKey := names.WorkloadEndpointIDToWorkloadEndpointKey(wepID, hostname)
		Expect(genKey).To(Equal(expectedKey))
	},
	Entry("Valid workload endpoint ID", &proto.WorkloadEndpointID{OrchestratorId: "k8s", WorkloadId: "default/testpod1", EndpointId: "eth0"}, "cluster-node-0", &model.WorkloadEndpointKey{Hostname: "cluster-node-0", OrchestratorID: "k8s", WorkloadID: "default/testpod1", EndpointID: "eth0"}),
	Entry("Nil ID", nil, "", nil),
)

var _ = DescribeTable("V3 WorkloadEndpoint to model WorkloadEndpointKey",
	func(ep *v3.WorkloadEndpoint, expectedKey *model.WorkloadEndpointKey) {
		genKey, err := names.V3WorkloadEndpointToWorkloadEndpointKey(ep)
		Expect(err).NotTo(HaveOccurred())
		Expect(genKey).To(BeEquivalentTo(expectedKey))
	},
	Entry("Valid, FV endpoint (etcd datastore)",
		&v3.WorkloadEndpoint{
			//"felixfv default%2Fworkload-endpoint-status-tests-0-idx7 workload-endpoint-status-tests-0-idx7"
			TypeMeta: v1.TypeMeta{
				Kind:       "WorkloadEndpoint",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: v1.ObjectMeta{
				Name:                       "felix--0--821432--15--felixfv-felixfv-workload--endpoint--status--tests--0--idx7-workload--endpoint--status--tests--0--idx7",
				GenerateName:               "",
				Namespace:                  "default",
				SelfLink:                   "",
				UID:                        "aed7dfc0-6f53-4634-af65-cef3fd4cf37e",
				ResourceVersion:            "4",
				Generation:                 0,
				CreationTimestamp:          v1.Time{},
				DeletionTimestamp:          nil,
				DeletionGracePeriodSeconds: nil,
				Labels:                     map[string]string{},
				Annotations:                nil,
				OwnerReferences:            nil,
				Finalizers:                 nil,
				ManagedFields:              nil,
			},
			Spec: v3.WorkloadEndpointSpec{
				Orchestrator:               "felixfv",
				Workload:                   "workload-endpoint-status-tests-0-idx7",
				Node:                       "felix-0-821432-15-felixfv",
				ContainerID:                "",
				Pod:                        "",
				Endpoint:                   "workload-endpoint-status-tests-0-idx7",
				ServiceAccountName:         "",
				IPNetworks:                 []string{},
				IPNATs:                     nil,
				IPv4Gateway:                "",
				IPv6Gateway:                "",
				Profiles:                   []string{},
				InterfaceName:              "cali32724719ad7",
				MAC:                        "",
				Ports:                      nil,
				AllowSpoofedSourcePrefixes: nil,
			},
		},
		&model.WorkloadEndpointKey{
			Hostname:       "felix-0-821432-15-felixfv",
			OrchestratorID: "felixfv",
			WorkloadID:     "default/workload-endpoint-status-tests-0-idx7",
			EndpointID:     "workload-endpoint-status-tests-0-idx7",
		},
	),

	Entry("Valid, FV endpoint (kubernetes datastore)",
		&v3.WorkloadEndpoint{
			//"k8s default%2Fworkload-endpoint-status-tests-0-idx3 eth0"
			TypeMeta: v1.TypeMeta{
				Kind:       "WorkloadEndpoint",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: v1.ObjectMeta{
				Name:                       "felix--0--821432--9--felixfv-k8s-workload--endpoint--status--tests--0--idx3-eth0",
				GenerateName:               "",
				Namespace:                  "default",
				SelfLink:                   "",
				UID:                        "8a102cd6-67a9-4b71-aa8c-b9a6938fdea8",
				ResourceVersion:            "263",
				Generation:                 0,
				CreationTimestamp:          v1.Time{},
				DeletionTimestamp:          nil,
				DeletionGracePeriodSeconds: nil,
				Labels:                     map[string]string{},
				Annotations:                nil,
				OwnerReferences:            nil,
				Finalizers:                 nil,
				ManagedFields:              nil,
			},
			Spec: v3.WorkloadEndpointSpec{
				Orchestrator:               "k8s",
				Workload:                   "workload-endpoint-status-tests-0-idx3",
				Node:                       "felix-0-821432-9-felixfv",
				ContainerID:                "",
				Pod:                        "workload-endpoint-status-tests-0-idx3",
				Endpoint:                   "eth0",
				ServiceAccountName:         "default",
				IPNetworks:                 []string{},
				IPNATs:                     nil,
				IPv4Gateway:                "",
				IPv6Gateway:                "",
				Profiles:                   []string{},
				InterfaceName:              "cali22bf70d285d",
				MAC:                        "",
				Ports:                      nil,
				AllowSpoofedSourcePrefixes: nil,
			},
		},
		&model.WorkloadEndpointKey{
			Hostname:       "felix-0-821432-9-felixfv",
			OrchestratorID: "k8s",
			WorkloadID:     "default/workload-endpoint-status-tests-0-idx3",
			EndpointID:     "eth0",
		},
	),

	Entry("Nil endpoint", nil, nil),
)
