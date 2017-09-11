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

package clientv2_test

import (
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/libcalico-go/lib/apiv2"
	"github.com/projectcalico/libcalico-go/lib/backend"
	"github.com/projectcalico/libcalico-go/lib/clientv2"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/testutils"
)

var order1 = 99.999
var order2 = 22.222

var policySpec1 = apiv2.PolicySpec{
	Order:        &order1,
	IngressRules: []apiv2.Rule{testutils.InRule1, testutils.InRule2},
	EgressRules:  []apiv2.Rule{testutils.EgressRule1, testutils.EgressRule2},
	Selector:     "thing == 'value'",
}

var policySpec2 = apiv2.PolicySpec{
	Order:        &order2,
	IngressRules: []apiv2.Rule{testutils.InRule2, testutils.InRule1},
	EgressRules:  []apiv2.Rule{testutils.EgressRule2, testutils.EgressRule1},
	Selector:     "thing2 == 'value2'",
	DoNotTrack:   true,
}

var policySpec3 = apiv2.PolicySpec{
	Order:        &order2,
	IngressRules: []apiv2.Rule{testutils.InRule2, testutils.InRule1},
	Selector:     "thing2 == 'value2'",
	PreDNAT:      true,
}

var egressPolicy = apiv2.PolicySpec{
	Order:       &order2,
	EgressRules: []apiv2.Rule{testutils.InRule2, testutils.InRule1},
	Selector:    "thing2 == 'value2'",
}

// Perform CRUD operations on Global and Node-specific BGP Peer Resources.
var _ = testutils.E2eDatastoreDescribe("NetworkPolicy tests", testutils.DatastoreAll, func(config apiconfig.CalicoAPIConfig) {

	DescribeTable("NetworkPolicy e2e tests",
		func(namespace1, namespace2, name1, name2 string, spec1, spec2 apiv2.PolicySpec) {
			c, err := clientv2.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			By("Updating the NetworkPolicy before it is created")
			res, outError := c.NetworkPolicies(namespace1).Update(&apiv2.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "1234"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("resource does not exist: NetworkPolicy(" + namespace1 + "/" + name1 + ")"))

			By("Attempting to creating a new NetworkPolicy with name1/spec1 and a non-empty ResourceVersion")
			res, outError = c.NetworkPolicies(namespace1).Create(&apiv2.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "12345"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(res).To(BeNil())
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '12345' (field must not be set for a Create request)"))

			By("Creating a new NetworkPolicy with namespace1/name1/spec1")
			res1, outError := c.NetworkPolicies(namespace1).Create(&apiv2.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: name1},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			assertNetworkPolicy(res1, name1, spec1)

			// Track the version of the original data for name1.
			rv1_1 := res1.ObjectMeta.ResourceVersion

			By("Attempting to create the same NetworkPolicy with name1 but with spec2")
			res1, outError = c.NetworkPolicies(namespace1).Create(&apiv2.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: name1},
				Spec:       spec2,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource already exists: NetworkPolicy(" + namespace1 + "/" + name1 + ")"))
			// Check return value is actually the previously stored value.
			assertNetworkPolicy(res1, name1, spec1)
			Expect(res1.ObjectMeta.ResourceVersion).To(Equal(rv1_1))

			By("Getting NetworkPolicy (name1) and comparing the output against spec1")
			res, outError = c.NetworkPolicies(namespace1).Get(name1, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			assertNetworkPolicy(res, name1, spec1)
			Expect(res.ObjectMeta.ResourceVersion).To(Equal(res1.ObjectMeta.ResourceVersion))

			By("Getting NetworkPolicy (name2) before it is created")
			res, outError = c.NetworkPolicies(namespace2).Get(name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource does not exist: NetworkPolicy(" + namespace2 + "/" + name2 + ")"))

			By("Listing all the NetworkPolicies in namespace1, expecting a single result with name1/spec1")
			outList, outError := c.NetworkPolicies(namespace1).List(options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(1))
			assertNetworkPolicy(&outList.Items[0], name1, spec1)

			By("Creating a new NetworkPolicy with name2/spec2")
			res2, outError := c.NetworkPolicies(namespace2).Create(&apiv2.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: name2, Namespace: namespace2},
				Spec:       spec2,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			assertNetworkPolicy(res2, name2, spec2)

			By("Getting NetworkPolicy (name2) and comparing the output against spec2")
			res, outError = c.NetworkPolicies(namespace2).Get(name2, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			assertNetworkPolicy(res, name2, spec2)
			Expect(res.ObjectMeta.ResourceVersion).To(Equal(res2.ObjectMeta.ResourceVersion))

			By("Listing all the NetworkPolicies using an empty namespace (all-namespaces), expecting a two results with name1/spec1 and name2/spec2")
			outList, outError = c.NetworkPolicies("").List(options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(2))
			assertNetworkPolicy(&outList.Items[0], name1, spec1)
			assertNetworkPolicy(&outList.Items[1], name2, spec2)

			By("Listing all the NetworkPolicies in namespace2, expecting a one results with name2/spec2")
			outList, outError = c.NetworkPolicies(namespace2).List(options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(1))
			assertNetworkPolicy(&outList.Items[0], name2, spec2)

			By("Updating NetworkPolicy name1 with spec2")
			res1.Spec = spec2
			res1, outError = c.NetworkPolicies(namespace1).Update(res1, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			assertNetworkPolicy(res1, name1, spec2)

			// Track the version of the updated name1 data.
			rv1_2 := res1.ObjectMeta.ResourceVersion

			By("Updating BGPPeer name1 without specifying a resource version")
			res1.Spec = spec1
			res1.ObjectMeta.ResourceVersion = ""
			res, outError = c.NetworkPolicies(namespace1).Update(res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '' (field must be set for an Update request)"))
			Expect(res).To(BeNil())

			By("Updating NetworkPolicy name1 using the previous resource version")
			res1.Spec = spec1
			res1.ObjectMeta.ResourceVersion = rv1_1
			res1, outError = c.NetworkPolicies(namespace1).Update(res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("update conflict: NetworkPolicy(" + namespace1 + "/" + name1 + ")"))
			Expect(res1.ObjectMeta.ResourceVersion).To(Equal(rv1_2))

			By("Getting NetworkPolicy (name1) with the original resource version and comparing the output against spec1")
			res, outError = c.NetworkPolicies(namespace1).Get(name1, options.GetOptions{ResourceVersion: rv1_1})
			Expect(outError).NotTo(HaveOccurred())
			assertNetworkPolicy(res, name1, spec1)
			Expect(res.ObjectMeta.ResourceVersion).To(Equal(rv1_1))

			By("Getting NetworkPolicy (name1) with the updated resource version and comparing the output against spec2")
			res, outError = c.NetworkPolicies(namespace1).Get(name1, options.GetOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			assertNetworkPolicy(res, name1, spec2)
			Expect(res.ObjectMeta.ResourceVersion).To(Equal(rv1_2))

			By("Listing NetworkPolicies with the original resource version and checking for a single result with name1/spec1")
			outList, outError = c.NetworkPolicies(namespace1).List(options.ListOptions{ResourceVersion: rv1_1})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(1))
			assertNetworkPolicy(&outList.Items[0], name1, spec1)

			By("Listing NetworkPolicies (all namespaces) with the latest resource version and checking for two results with name1/spec2 and name2/spec2")
			outList, outError = c.NetworkPolicies("").List(options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(2))
			assertNetworkPolicy(&outList.Items[0], name1, spec2)
			assertNetworkPolicy(&outList.Items[1], name2, spec2)

			By("Deleting NetworkPolicy (name1) with the old resource version")
			outError = c.NetworkPolicies(namespace1).Delete(name1, options.DeleteOptions{ResourceVersion: rv1_1})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("update conflict: NetworkPolicy(" + namespace1 + "/" + name1 + ")"))

			By("Deleting NetworkPolicy (name1) with the new resource version")
			outError = c.NetworkPolicies(namespace1).Delete(name1, options.DeleteOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())

			By("Updating NetworkPolicy name2 with a 2s TTL and waiting for the entry to be deleted")
			_, outError = c.NetworkPolicies(namespace2).Update(res2, options.SetOptions{TTL: 2 * time.Second})
			Expect(outError).NotTo(HaveOccurred())
			time.Sleep(1 * time.Second)
			_, outError = c.NetworkPolicies(namespace2).Get(name2, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			time.Sleep(2 * time.Second)
			_, outError = c.NetworkPolicies(namespace2).Get(name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource does not exist: NetworkPolicy(" + namespace2 + "/" + name2 + ")"))

			By("Creating NetworkPolicy name2 with a 2s TTL and waiting for the entry to be deleted")
			_, outError = c.NetworkPolicies(namespace2).Create(&apiv2.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: name2},
				Spec:       spec2,
			}, options.SetOptions{TTL: 2 * time.Second})
			Expect(outError).NotTo(HaveOccurred())
			time.Sleep(1 * time.Second)
			_, outError = c.NetworkPolicies(namespace2).Get(name2, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			time.Sleep(2 * time.Second)
			_, outError = c.NetworkPolicies(namespace2).Get(name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource does not exist: NetworkPolicy(" + namespace2 + "/" + name2 + ")"))

			By("Attempting to deleting NetworkPolicy (name2) again")
			outError = c.NetworkPolicies(namespace2).Delete(name2, options.DeleteOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource does not exist: NetworkPolicy(" + namespace2 + "/" + name2 + ")"))

			By("Listing all NetworkPolicies and expecting no items")
			outList, outError = c.NetworkPolicies("").List(options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))

			By("Getting NetworkPolicy (name2) and expecting an error")
			res, outError = c.NetworkPolicies(namespace2).Get(name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource does not exist: NetworkPolicy(" + namespace2 + "/" + name2 + ")"))
		},

		// Test 1: Pass two fully populated PolicySpecs and expect the series of operations to succeed.
		Entry("Two fully populated PolicySpecs",
			"namespace-1",
			"namespace-2",
			"networkp-1",
			"networkp-2",
			policySpec1,
			policySpec2,
		),
	)
})

func assertNetworkPolicy(res *apiv2.NetworkPolicy, name string, spec apiv2.PolicySpec) {
	Expect(res.ObjectMeta.Name).To(Equal(name))
	Expect(res.Spec).To(Equal(spec))
	Expect(res.ObjectMeta.ResourceVersion).NotTo(BeEmpty())
	Expect(res.TypeMeta.Kind).To(Equal("NetworkPolicy"))
	Expect(res.TypeMeta.APIVersion).To(Equal("projectcalico.org/v2"))
}
