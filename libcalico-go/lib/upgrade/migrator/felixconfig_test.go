// Copyright (c) 2017-2018 Tigera, Inc. All rights reserved.

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

package migrator

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

var _ = Describe("Test felix configuration upgrade", func() {
	// Define some common values
	seconds1 := metav1.Duration{Duration: time.Duration(12.345 * float64(time.Second))}
	millis1 := metav1.Duration{Duration: time.Duration(50.325 * float64(time.Millisecond))}
	bool1 := false
	uint1 := uint32(1313)
	seconds2 := metav1.Duration{Duration: time.Duration(32.222 * float64(time.Second))}
	millis2 := metav1.Duration{Duration: time.Duration(10.754 * float64(time.Millisecond))}
	bool2 := true
	uint2 := uint32(1414)
	perNodeFelixKey := model.ResourceKey{
		Kind: apiv3.KindFelixConfiguration,
		Name: "node.mynode",
	}

	perNodeFelix := apiv3.NewFelixConfiguration()
	perNodeFelix.Name = "node.mynode"
	perNodeFelix.Spec = apiv3.FelixConfigurationSpec{
		RouteRefreshInterval:      &seconds1,
		IptablesLockProbeInterval: &millis1,
		InterfacePrefix:           "califoobar",
		IPIPEnabled:               &bool1,
		IptablesMarkMask:          &uint1,
		FailsafeInboundHostPorts:  &[]apiv3.ProtoPort{},
		FailsafeOutboundHostPorts: &[]apiv3.ProtoPort{
			{
				Protocol: "TCP",
				Port:     1234,
				Net:      "0.0.0.0/0",
			},
			{
				Protocol: "UDP",
				Port:     22,
				Net:      "0.0.0.0/0",
			},
			{
				Protocol: "TCP",
				Port:     65535,
				Net:      "0.0.0.0/0",
			},
		},
	}

	globalFelixKey := model.ResourceKey{
		Kind: apiv3.KindFelixConfiguration,
		Name: "default",
	}
	globalFelix := apiv3.NewFelixConfiguration()
	globalFelix.Name = "default"
	globalFelix.Spec = apiv3.FelixConfigurationSpec{
		RouteRefreshInterval:      &seconds2,
		IptablesLockProbeInterval: &millis2,
		InterfacePrefix:           "califoobar",
		IPIPEnabled:               &bool2,
		IptablesMarkMask:          &uint2,
		FailsafeInboundHostPorts: &[]apiv3.ProtoPort{
			{
				Protocol: "TCP",
				Port:     1234,
				Net:      "0.0.0.0/0",
			},
			{
				Protocol: "UDP",
				Port:     22,
				Net:      "0.0.0.0/0",
			},
			{
				Protocol: "TCP",
				Port:     65535,
				Net:      "0.0.0.0/0",
			},
		},
	}

	globalClusterKey := model.ResourceKey{
		Kind: apiv3.KindClusterInformation,
		Name: "default",
	}
	globalCluster := apiv3.NewClusterInformation()
	globalCluster.Name = "default"
	globalCluster.Spec = apiv3.ClusterInformationSpec{
		ClusterGUID:    "abcedfg",
		ClusterType:    "Mesos,K8s",
		DatastoreReady: &bool1,
	}

	It("should handle different field types being assigned", func() {
		clientv1 := fakeClientV1{}

		By("using an update processor to create v1 KVPairs from per-node FelixConfiguration")
		cp := updateprocessors.NewFelixConfigUpdateProcessor()
		kvps, err := cp.Process(&model.KVPair{
			Key:   perNodeFelixKey,
			Value: perNodeFelix,
		})
		Expect(err).NotTo(HaveOccurred())
		clientv1.kvps = kvps

		By("using an update processor to create v1 KVPairs from global FelixConfiguration")
		cp = updateprocessors.NewFelixConfigUpdateProcessor()
		kvps, err = cp.Process(&model.KVPair{
			Key:   globalFelixKey,
			Value: globalFelix,
		})
		Expect(err).NotTo(HaveOccurred())
		clientv1.kvps = append(clientv1.kvps, kvps...)

		By("using an update processor to create v1 KVPairs from global ClusterInformation")
		cp = updateprocessors.NewClusterInfoUpdateProcessor()
		kvps, err = cp.Process(&model.KVPair{
			Key:   globalClusterKey,
			Value: globalCluster,
		})
		Expect(err).NotTo(HaveOccurred())
		clientv1.kvps = append(clientv1.kvps, kvps...)

		// Convert the data back to a set of resources.
		data := &MigrationData{}
		mh := &migrationHelper{clientv1: clientv1}
		err = mh.queryAndConvertFelixConfigV1ToV3(data)
		Expect(err).NotTo(HaveOccurred())
		By("Checking total conversion is 3")
		Expect(data.Resources).To(HaveLen(3))
		By("Checking global felix config")
		Expect(data.Resources[0]).To(Equal(globalFelix))
		By("Checking global cluster info")
		Expect(data.Resources[1]).To(Equal(globalCluster))
		By("Checking per node felix config")
		Expect(data.Resources[2]).To(Equal(perNodeFelix))
	})
})

type fakeClientV1 struct {
	kdd  bool
	kvps []*model.KVPair
}

func (fc fakeClientV1) Apply(d *model.KVPair) (*model.KVPair, error) {
	return nil, nil
}

func (fc fakeClientV1) Update(d *model.KVPair) (*model.KVPair, error) {
	return nil, nil
}

func (fc fakeClientV1) Get(k model.Key) (*model.KVPair, error) {
	ks := k.String()
	for _, kvp := range fc.kvps {
		if kvp.Key.String() == ks {
			return kvp, nil
		}
	}
	return nil, cerrors.ErrorResourceDoesNotExist{Identifier: k}
}

func (fc fakeClientV1) List(l model.ListInterface) ([]*model.KVPair, error) {
	r := []*model.KVPair{}
	_, isPL := l.(model.ProfileListOptions)
	for _, kvp := range fc.kvps {
		p, _ := model.KeyToDefaultPath(kvp.Key)
		if l.KeyFromDefaultPath(p) != nil {
			r = append(r, kvp)
			// This profile specific check allows adding a ProfileKey in the kvps
			// that does not get matched with the above To/From DefaultPath check.
			// The normal client would return a ProfileKey as it does the work of
			// combining the rules/tags/labels.
		} else if _, ok := kvp.Key.(model.ProfileKey); ok && isPL {
			r = append(r, kvp)
		}
	}
	return r, nil
}

func (fc fakeClientV1) IsKDD() bool {
	return fc.kdd
}
