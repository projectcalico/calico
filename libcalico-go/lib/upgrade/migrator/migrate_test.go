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
	"context"
	"errors"
	gnet "net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/upgrade/converters"
	"github.com/projectcalico/calico/libcalico-go/lib/upgrade/migrator/clients"
)

var _ = Describe("UT for checking the version for migration.", func() {

	DescribeTable("Checking canMigrate.",
		func(ver string, result bool, resultHasError bool) {
			yes, err := versionRequiresMigration(ver)

			if resultHasError {
				Expect(err).To(HaveOccurred())
			} else {
				Expect(err).NotTo(HaveOccurred())
				Expect(yes).To(Equal(result))
			}
		},

		Entry("Expect v2.6.5 to migrate", "v2.6.5", true, false),
		Entry("Expect v2.6.5-rc1 to migrate", "v2.6.5-rc1", true, false),
		Entry("Expect v2.6.5-15-g0986c6cd to migrate", "v2.6.5-15-g0986c6cd", true, false),
		Entry("Expect v2.6.6 to migrate", "v2.6.6", true, false),
		Entry("Expect v2.6.6-rc1 to migrate", "v2.6.6-rc1", true, false),
		Entry("Expect v2.7.0 to migrate", "v2.7.0", true, false),
		Entry("Expect v2.7.0-rc1 to migrate", "v2.7.0-rc1", true, false),
		Entry("Expect v2.6.4 to not migrate", "v2.6.4", false, true),
		Entry("Expect v2.6.4-rc1 to not migrate", "v2.6.4-rc1", false, true),
		Entry("Expect v2.6.4-15-g0986c6cd to not migrate", "v2.6.4-15-g0986c6cd", false, true),
		Entry("Expect v2.6.x-deadbeef to not migrate", "v2.6.x-deadbeef", false, true),
		Entry("Expect v3.0 to not migrate", "v3.0", false, true),
		Entry("Expect v3.0.0 to not migrate", "v3.0.0", false, false),
		Entry("Expect v3.0.0-beta1 to not migrate", "v3.0.0-beta1", false, false),
		Entry("Expect v3.0.0-0 to not migrate", "v3.0.0-0", false, false),
		Entry("Expect v3.0.0-a to not migrate", "v3.0.0-a", false, false),
		Entry("Expect v3.0.0-beta1-128-g1caef47d to not migrate", "v3.0.0-beta1-128-g1caef47d", false, false),
		Entry("Expect master to not migrate", "master", false, true),
		Entry("Expect empty string to not migrate", "", false, true),
		Entry("Expect garbage to not migrate", "garbage", false, true),
		Entry("Expect 1.2.3.4.5 to not migrate", "1.2.3.4.5", false, true),
	)
})

func convertAndCheckResourcesConverted(client clients.V1ClientInterface, expectedConversionCount int) {
	// Convert the data back to a set of resources.
	mh := &migrationHelper{clientv1: client}
	data, err := mh.queryAndConvertResources()
	Expect(err).NotTo(HaveOccurred())
	Expect(data.ConversionErrors).To(HaveLen(0))
	By("Checking total conversion")
	Expect(data.Resources).To(HaveLen(expectedConversionCount))
}

var _ = Describe("Test OpenStack migration filters", func() {

	wk := model.WorkloadEndpointKey{
		Hostname:       "ahost",
		OrchestratorID: "orchestrator",
		WorkloadID:     "wkid",
		EndpointID:     "endID",
	}
	mac, _ := gnet.ParseMAC("ee:ee:ee:ee:ee:ee")
	wv := model.WorkloadEndpoint{
		State:            "Running",
		Name:             "wepName",
		ActiveInstanceID: "wepActInstID",
		Mac:              &net.MAC{mac},
		ProfileIDs:       []string{"wepProfIDs"},
		IPv4Nets:         []net.IPNet{},
		IPv6Nets:         []net.IPNet{},
	}

	It("should not filter WorkloadEndpoints without openstack as OrchestratorID", func() {
		clientv1 := fakeClientV1{
			kvps: []*model.KVPair{
				{
					Key:   wk,
					Value: &wv,
				},
			},
		}

		convertAndCheckResourcesConverted(clientv1, 1)
	})

	It("should filter WorkloadEndpoints with openstack as OrchestratorID", func() {
		wepOSKey := wk
		wepOSKey.OrchestratorID = v3.OrchestratorOpenStack
		clientv1 := fakeClientV1{
			kvps: []*model.KVPair{
				{
					Key:   wepOSKey,
					Value: &wv,
				},
			},
		}

		convertAndCheckResourcesConverted(clientv1, 0)
	})

	It("should not filter Profiles without openstack-sg prefix", func() {
		clientv1 := fakeClientV1{
			kvps: []*model.KVPair{
				{
					Key: model.ProfileKey{
						Name: "profilename",
					},
					Value: &model.Profile{
						Rules: model.ProfileRules{
							InboundRules: []model.Rule{converters.V1ModelInRule1},
						},
						Tags:   []string{},
						Labels: map[string]string{"label1": "value1"},
					},
				},
			},
		}

		convertAndCheckResourcesConverted(clientv1, 1)
	})
	It("should filter Profiles with openstack-sg- prefix", func() {
		clientv1 := fakeClientV1{
			kvps: []*model.KVPair{
				{
					Key: model.ProfileKey{
						Name: "openstack-sg-profilename",
					},
					Value: &model.Profile{
						Rules: model.ProfileRules{
							InboundRules: []model.Rule{converters.V1ModelInRule1},
						},
						Tags:   []string{},
						Labels: map[string]string{"label1": "value1"},
					},
				},
			},
		}

		convertAndCheckResourcesConverted(clientv1, 0)
	})
})

var _ = testutils.E2eDatastoreDescribe("Migration tests", testutils.DatastoreEtcdV3, func(config apiconfig.CalicoAPIConfig) {

	ctx := context.Background()
	blank := ""
	v2_6_4 := "v2.6.4"
	v2_6_5 := "v2.6.5"
	v3_0_0 := "v3.0.0"
	v3_1_0 := "v3.1.0"
	master := "master"

	DescribeTable("ShouldMigrate() tests",
		func(v1Version, v3Version *string, expected interface{}) {
			// For the v1 version, we use the emulated client since this is an easy implementation.
			// For the v3 version, we hook into etcdv3 using the real v3 client.
			v3Client, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			// Clean the v3 data.
			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			// If the v3 version is specified, configure it in the ClusterInformation.
			By("Configuring a cluster version in the v3 datastore")
			if v3Version != nil {
				_, err := v3Client.ClusterInformation().Create(ctx, &v3.ClusterInformation{
					ObjectMeta: v1.ObjectMeta{
						Name: "default",
					},
					Spec: v3.ClusterInformationSpec{
						CalicoVersion: *v3Version,
					},
				}, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())
			}

			// Create the dummy v1 client, if necessary including the v1 cluster version.
			By("Configuring a cluster version in the v1 datastore")
			v1Client := fakeClientV1{}
			if v1Version != nil {
				v1Client.kvps = append(v1Client.kvps, &model.KVPair{
					Key:   model.GlobalConfigKey{Name: "CalicoVersion"},
					Value: *v1Version,
				})
			}

			// Create the migration helper.
			By("Creating a migration helper and invoking ShouldMigrate()")
			mh := &migrationHelper{clientv1: v1Client, clientv3: v3Client}
			s, err := mh.ShouldMigrate()
			if b, ok := expected.(bool); ok {
				Expect(err).NotTo(HaveOccurred())
				Expect(s).To(Equal(b))
			} else {
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal(expected.(error).Error()))
				Expect(s).To(BeFalse())
			}
		},

		// Test 1: Pass two fully populated BGPConfigurationSpecs and expect the series of operations to succeed.
		Entry("No calico version data", nil, nil, false),
		Entry("v1 only calico version (v2.6.4)", &v2_6_4, nil,
			errors.New("unable to migrate data from version 'v2.6.4': migration to "+
				"v3 requires a tagged release of Calico v2.6.5+")),
		Entry("v1 only calico version (v2.6.5)", &v2_6_5, nil, true),
		Entry("v1 only calico version (v3.0.0)", &v3_0_0, nil,
			errors.New("unexpected Calico version 'v3.0.0': migration to v3 should be from a tagged "+
				"release of Calico v2.6.5+")),
		Entry("v1 only calico version (master)", &master, nil,
			errors.New("unable to migrate data from version 'master': unable to parse the version")),
		Entry("v3 only calico version (v2.6.4)", nil, &v2_6_4,
			errors.New("unexpected CalicoVersion 'v2.6.4' in ClusterInformation: migration to v3 requires a tagged "+
				"release of Calico v2.6.5+")),
		Entry("v1 and v3 calico version (v2.6.5)", &v2_6_5, &v2_6_5, true),
		Entry("v1 and v3 calico version (v2.6.5 and v3.0.0 resp)", &v2_6_5, &v3_0_0, false),
		Entry("v1 and v3 calico version (v2.6.5 and v3.1.0 resp)", &v2_6_5, &v3_1_0, false),
		Entry("v1 and v3 calico version (v2.6.5 and blank resp)", &v2_6_5, &blank, true),
		Entry("v1 and v3 calico version (blank)", &blank, &blank,
			errors.New("unable to migrate data from version '': unable to parse the version")),
		Entry("v3 only calico version (blank)", nil, &blank, false),
	)
})
