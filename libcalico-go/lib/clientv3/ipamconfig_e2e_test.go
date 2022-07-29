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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

var _ = testutils.E2eDatastoreDescribe("IPAMConfig tests", testutils.DatastoreAll, func(config apiconfig.CalicoAPIConfig) {
	ctx := context.Background()
	name := "default"
	spec1 := libapiv3.IPAMConfigSpec{
		StrictAffinity:     true,
		AutoAllocateBlocks: true,
		MaxBlocksPerHost:   2,
	}
	spec2 := libapiv3.IPAMConfigSpec{
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

	DescribeTable("IPAMConfig e2e CRUD tests",
		func(name string, spec1, spec2 libapiv3.IPAMConfigSpec) {
			By("Updating the IPAMConfig before it is created")
			_, outError := c.IPAMConfig().Update(ctx, &libapiv3.IPAMConfig{
				ObjectMeta: metav1.ObjectMeta{Name: name, ResourceVersion: "1234", CreationTimestamp: metav1.Now(), UID: "test-fail-ipamconfig"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: IPAMConfig(" + name + ") with error:"))

			By("Attempting to creating a new IPAMConfig with spec1 and a non-empty ResourceVersion")
			_, outError = c.IPAMConfig().Create(ctx, &libapiv3.IPAMConfig{
				ObjectMeta: metav1.ObjectMeta{Name: name, ResourceVersion: "12345"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '12345' (field must not be set for a Create request)"))

			By("Getting IPAMConfig before it is created")
			_, outError = c.IPAMConfig().Get(ctx, name, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: IPAMConfig(" + name + ") with error:"))

			By("Attempting to create a new IPAMConfig with a non-default name and spec1")
			_, outError = c.IPAMConfig().Create(ctx, &libapiv3.IPAMConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "not-default"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("Cannot create a IPAMConfiguration resource with a name other than \"default\""))

			By("Creating a new IPAMConfig with spec1")
			res1, outError := c.IPAMConfig().Create(ctx, &libapiv3.IPAMConfig{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res1).To(MatchResource(libapiv3.KindIPAMConfig, testutils.ExpectNoNamespace, name, spec1))
			Expect(res1.GroupVersionKind).To(Equal(schema.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: "IPAMConfiguration"}))

			By("Attempting to create the same IPAMConfig but with spec2")
			_, outError = c.IPAMConfig().Create(ctx, &libapiv3.IPAMConfig{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec:       spec2,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource already exists: IPAMConfig(" + name + ")"))

			By("Getting IPAMConfig and comparing the output against spec1")
			res, outError := c.IPAMConfig().Get(ctx, name, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(libapiv3.KindIPAMConfig, testutils.ExpectNoNamespace, name, spec1))
			Expect(res.ResourceVersion).To(Equal(res1.ResourceVersion))
			Expect(res.GroupVersionKind).To(Equal(schema.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: "IPAMConfiguration"}))

			By("Updating IPAMConfig with spec2")
			res1.Spec = spec2
			res1, outError = c.IPAMConfig().Update(ctx, res1, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res1).To(MatchResource(libapiv3.KindIPAMConfig, testutils.ExpectNoNamespace, name, spec2))

			By("Attempting to update the IPAMConfig without a Creation Timestamp")
			res, outError = c.IPAMConfig().Update(ctx, &libapiv3.IPAMConfig{
				ObjectMeta: metav1.ObjectMeta{Name: name, ResourceVersion: "1234", UID: "test-fail-ipamconfig"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("error with field Metadata.CreationTimestamp = '0001-01-01 00:00:00 +0000 UTC' (field must be set for an Update request)"))

			By("Attempting to update the IPAMConfig without a UID")
			res, outError = c.IPAMConfig().Update(ctx, &libapiv3.IPAMConfig{
				ObjectMeta: metav1.ObjectMeta{Name: name, ResourceVersion: "1234", CreationTimestamp: metav1.Now()},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("error with field Metadata.UID = '' (field must be set for an Update request)"))

			By("Deleting IPAMConfig with the new resource version")
			dres, outError := c.IPAMConfig().Delete(ctx, name, options.DeleteOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(dres).To(testutils.MatchResource(libapiv3.KindIPAMConfig, testutils.ExpectNoNamespace, name, spec2))

			By("Listing IPAMConfig and expecting error")
			l, outError := c.IPAMConfig().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			for _, res := range l.Items {
				Expect(res.GroupVersionKind).To(Equal(schema.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: "IPAMConfiguration"}))
			}
		},

		// Test 1: Pass two fully populated IPAMConfigSpecs and expect the series of operations to succeed.
		Entry("Two fully populated IPAMConfigSpecs", name, spec1, spec2),
	)

	It("should reject MaxBlocksPerHost less than zero", func() {
		_, err := c.IPAMConfig().Create(ctx, &libapiv3.IPAMConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: libapiv3.IPAMConfigSpec{
				MaxBlocksPerHost: -1,
			},
		}, options.SetOptions{})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Equal("error with field MaxBlocksPerHost = '-1' (must be greater than or equal to 0)"))
	})
})
