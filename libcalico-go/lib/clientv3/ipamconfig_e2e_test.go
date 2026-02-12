// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package clientv3_test

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

var _ = testutils.E2eDatastoreDescribe("IPAMConfiguration tests", testutils.DatastoreAll, func(config apiconfig.CalicoAPIConfig) {
	ctx := context.Background()
	name := "default"
	spec1 := v3.IPAMConfigurationSpec{
		StrictAffinity:     true,
		AutoAllocateBlocks: true,
		MaxBlocksPerHost:   2,
	}
	spec2 := v3.IPAMConfigurationSpec{
		StrictAffinity:     false,
		AutoAllocateBlocks: true,
		MaxBlocksPerHost:   0,
	}

	var c clientv3.Interface
	var be bapi.Client

	BeforeEach(func() {
		var err error
		c, err = clientv3.New(config)
		Expect(err).NotTo(HaveOccurred())

		be, err = backend.NewClient(config)
		Expect(err).NotTo(HaveOccurred())
		err = be.Clean()
		Expect(err).NotTo(HaveOccurred())
	})

	DescribeTable("IPAMConfiguration e2e CRUD tests",
		func(name string, spec1, spec2 v3.IPAMConfigurationSpec) {
			By("Updating the IPAMConfiguration before it is created")
			_, outError := c.IPAMConfiguration().Update(ctx, &v3.IPAMConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: name, ResourceVersion: "1234", CreationTimestamp: metav1.Now(), UID: uid},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: IPAMConfiguration(" + name + ") with error:"))

			By("Attempting to creating a new IPAMConfiguration with spec1 and a non-empty ResourceVersion")
			_, outError = c.IPAMConfiguration().Create(ctx, &v3.IPAMConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: name, ResourceVersion: "12345"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '12345' (field must not be set for a Create request)"))

			By("Getting IPAMConfiguration before it is created")
			_, outError = c.IPAMConfiguration().Get(ctx, name, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: IPAMConfiguration(" + name + ") with error:"))

			By("Attempting to create a new IPAMConfiguration with a non-default name and spec1")
			_, outError = c.IPAMConfiguration().Create(ctx, &v3.IPAMConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: "not-default"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("Cannot create an IPAMConfiguration resource with a name other than \"default\""))

			By("Creating a new IPAMConfiguration with spec1")
			res1, outError := c.IPAMConfiguration().Create(ctx, &v3.IPAMConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res1).To(MatchResource(v3.KindIPAMConfiguration, testutils.ExpectNoNamespace, name, spec1))
			Expect(res1.GroupVersionKind()).To(Equal(schema.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: "IPAMConfiguration"}))

			By("Attempting to create the same IPAMConfiguration but with spec2")
			_, outError = c.IPAMConfiguration().Create(ctx, &v3.IPAMConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec:       spec2,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource already exists: IPAMConfiguration(" + name + ")"))

			By("Getting IPAMConfiguration and comparing the output against spec1")
			res, outError := c.IPAMConfiguration().Get(ctx, name, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(v3.KindIPAMConfiguration, testutils.ExpectNoNamespace, name, spec1))
			Expect(res.ResourceVersion).To(Equal(res1.ResourceVersion))
			Expect(res.GroupVersionKind()).To(Equal(schema.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: "IPAMConfiguration"}))

			By("Updating IPAMConfiguration with spec2")
			res1.Spec = spec2
			res1, outError = c.IPAMConfiguration().Update(ctx, res1, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res1).To(MatchResource(v3.KindIPAMConfiguration, testutils.ExpectNoNamespace, name, spec2))

			By("Attempting to update the IPAMConfiguration without a Creation Timestamp")
			res, outError = c.IPAMConfiguration().Update(ctx, &v3.IPAMConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: name, ResourceVersion: "1234", UID: uid},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("error with field Metadata.CreationTimestamp = '0001-01-01 00:00:00 +0000 UTC' (field must be set for an Update request)"))

			By("Attempting to update the IPAMConfiguration without a UID")
			res, outError = c.IPAMConfiguration().Update(ctx, &v3.IPAMConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: name, ResourceVersion: "1234", CreationTimestamp: metav1.Now()},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("error with field Metadata.UID = '' (field must be set for an Update request)"))

			By("Deleting IPAMConfiguration with the new resource version")
			dres, outError := c.IPAMConfiguration().Delete(ctx, name, options.DeleteOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(dres).To(testutils.MatchResource(v3.KindIPAMConfiguration, testutils.ExpectNoNamespace, name, spec2))

			By("Listing IPAMConfiguration and expecting error")
			l, outError := c.IPAMConfiguration().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			for _, res := range l.Items {
				Expect(res.GroupVersionKind()).To(Equal(schema.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: "IPAMConfiguration"}))
			}
		},

		// Test 1: Pass two fully populated IPAMConfigurationSpecs and expect the series of operations to succeed.
		Entry("Two fully populated IPAMConfigurationSpecs", name, spec1, spec2),
	)

	It("should reject MaxBlocksPerHost less than zero", func() {
		_, err := c.IPAMConfiguration().Create(ctx, &v3.IPAMConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: v3.IPAMConfigurationSpec{
				MaxBlocksPerHost: -1,
			},
		}, options.SetOptions{})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Equal("error with field MaxBlocksPerHost = '-1' (must be greater than or equal to 0)"), err.Error())
	})
})
