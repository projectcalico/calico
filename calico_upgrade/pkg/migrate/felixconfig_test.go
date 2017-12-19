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

package migrate

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
)

var _ = Describe("Test felix configuration upgrade", func() {
	// Define some common values
	int1 := int(12345)
	bool1 := false
	uint1 := uint32(1313)
	int2 := int(12222)
	bool2 := true
	uint2 := uint32(1414)
	perNodeFelixKey := model.ResourceKey{
		Kind: apiv3.KindFelixConfiguration,
		Name: "node.mynode",
	}
	perNodeFelix := &apiv3.FelixConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "node.mynode"},
		Spec: apiv3.FelixConfigurationSpec{
			RouteRefreshIntervalSecs: &int1,
			InterfacePrefix:          "califoobar",
			IPIPEnabled:              &bool1,
			IptablesMarkMask:         &uint1,
			FailsafeInboundHostPorts: &[]apiv3.ProtoPort{},
			FailsafeOutboundHostPorts: &[]apiv3.ProtoPort{
				{
					Protocol: "TCP",
					Port:     1234,
				},
				{
					Protocol: "UDP",
					Port:     22,
				},
				{
					Protocol: "TCP",
					Port:     65535,
				},
			},
		},
	}
	globalFelixKey := model.ResourceKey{
		Kind: apiv3.KindFelixConfiguration,
		Name: "default",
	}
	globalFelix := &apiv3.FelixConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: apiv3.FelixConfigurationSpec{
			RouteRefreshIntervalSecs: &int2,
			InterfacePrefix:          "califoobar",
			IPIPEnabled:              &bool2,
			IptablesMarkMask:         &uint2,
			FailsafeInboundHostPorts: &[]apiv3.ProtoPort{
				{
					Protocol: "TCP",
					Port:     1234,
				},
				{
					Protocol: "UDP",
					Port:     22,
				},
				{
					Protocol: "TCP",
					Port:     65535,
				},
			},
		},
	}
	globalClusterKey := model.ResourceKey{
		Kind: apiv3.KindClusterInformation,
		Name: "default",
	}
	globalCluster := &apiv3.ClusterInformation{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: apiv3.ClusterInformationSpec{
			ClusterGUID:    "abcedfg",
			ClusterType:    "Mesos,K8s",
			DatastoreReady: &bool2,
		},
	}

	It("should handle different field types being assigned", func() {
		client := fakeClient{}

		By("using an update processor to create v1 KVPairs from per-node FelixConfiguration")
		cp := updateprocessors.NewFelixConfigUpdateProcessor()
		kvps, err := cp.Process(&model.KVPair{
			Key:   perNodeFelixKey,
			Value: perNodeFelix,
		})
		Expect(err).NotTo(HaveOccurred())
		client.kvps = kvps

		By("using an update processor to create v1 KVPairs from global FelixConfiguration")
		cp = updateprocessors.NewFelixConfigUpdateProcessor()
		kvps, err = cp.Process(&model.KVPair{
			Key:   globalFelixKey,
			Value: globalFelix,
		})
		Expect(err).NotTo(HaveOccurred())
		client.kvps = append(client.kvps, kvps...)

		By("using an update processor to create v1 KVPairs from global ClusterInformation")
		cp = updateprocessors.NewClusterInfoUpdateProcessor()
		kvps, err = cp.Process(&model.KVPair{
			Key:   globalClusterKey,
			Value: globalCluster,
		})
		Expect(err).NotTo(HaveOccurred())
		client.kvps = append(client.kvps, kvps...)

		// Convert the data back to a set of resources.
		data := &ConvertedData{}
		fc := &felixConfig{}
		err = fc.queryAndConvertFelixConfigV1ToV3(client, data)
		Expect(err).NotTo(HaveOccurred())
		Expect(data.Resources).To(HaveLen(3))
		Expect(data.Resources[0]).To(Equal(globalFelix))
		Expect(data.Resources[2]).To(Equal(globalCluster))
		Expect(data.Resources[3]).To(Equal(perNodeFelix))
	})
})

type fakeClient struct {
	kdd  bool
	kvps []*model.KVPair
}

func (fc fakeClient) Apply(d *model.KVPair) (*model.KVPair, error) {
	return nil, nil
}

func (fc fakeClient) Get(k model.Key) (*model.KVPair, error) {
	ks := k.String()
	for _, kvp := range fc.kvps {
		if kvp.Key.String() == ks {
			return kvp, nil
		}
	}
	return nil, cerrors.ErrorResourceDoesNotExist{Identifier: k}
}

func (fc fakeClient) List(l model.ListInterface) ([]*model.KVPair, error) {
	r := []*model.KVPair{}
	for _, kvp := range fc.kvps {
		p, _ := model.KeyToDefaultPath(kvp.Key)
		if l.KeyFromDefaultPath(p) != nil {
			r = append(r, kvp)
		}
	}
	return r, nil
}

func (fc fakeClient) IsKDD() bool {
	return fc.kdd
}
