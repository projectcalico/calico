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

package resources_test

import (
	"context"
	"encoding/json"
	"io"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/client/clientset_generated/clientset/scheme"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest/fake"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

var _ = testutils.E2eDatastoreDescribe("IPAM affinity k8s backend tests", testutils.DatastoreK8s, func(config apiconfig.CalicoAPIConfig) {
	It("should properly handle the deleted flag", func() {
		be, err := backend.NewClient(config)
		Expect(err).NotTo(HaveOccurred())
		be.Clean()

		// Create a new block affinity.
		kvp := model.KVPair{
			Key: model.BlockAffinityKey{
				Host:         "my-host",
				CIDR:         net.MustParseCIDR("192.168.1.0/24"),
				AffinityType: string(ipam.AffinityTypeHost),
			},
			Value: &model.BlockAffinity{
				State:   model.StateConfirmed,
				Deleted: false,
			},
		}
		_, err = be.Create(context.Background(), &kvp)
		Expect(err).NotTo(HaveOccurred())

		// Check that it can be seen.
		newKVP, err := be.Get(context.Background(), kvp.Key, "")
		Expect(err).NotTo(HaveOccurred())

		// Update it to be deleted.
		newKVP.Value.(*model.BlockAffinity).Deleted = true
		_, err = be.Update(context.Background(), newKVP)

		// Can no longer see it.
		_, err = be.Get(context.Background(), kvp.Key, "")
		Expect(err).To(HaveOccurred())
		Expect(err).To(BeAssignableToTypeOf(errors.ErrorResourceDoesNotExist{}))
	})
})

var _ = Describe("BlockAffinityClient tests with fake REST client", func() {
	var client resources.K8sResourceClient
	var fakeREST *fake.RESTClient

	Context("v3.BlockAffinity tests", func() {
		BeforeEach(func() {
			fakeREST = &fake.RESTClient{
				NegotiatedSerializer: serializer.WithoutConversionCodecFactory{CodecFactory: scheme.Codecs},
				GroupVersion: schema.GroupVersion{
					Group:   "crd.projectcalico.org",
					Version: "v1",
				},
				VersionedAPIPath: "/apis",
			}
			client = resources.NewBlockAffinityClientV3(fakeREST, resources.BackingAPIGroupV1)
		})

		It("should list all", func() {
			l, err := client.List(context.TODO(), model.ResourceListOptions{
				Kind: apiv3.KindBlockAffinity,
			}, "")

			// Expect an error since the client is not implemented.
			Expect(err).To(HaveOccurred())
			Expect(l).To(BeNil())

			// But we should be able to check the request...
			url := fakeREST.Req.URL
			logrus.Debug("URL: ", url)
			Expect(url.Path).To(Equal("/apis/blockaffinities"))
			Expect(url.Query()).NotTo(HaveKey("metadata.name"))
		})

		It("should use a fieldSelector for a list name match", func() {
			l, err := client.List(context.TODO(), model.ResourceListOptions{
				Name: "foo",
				Kind: apiv3.KindBlockAffinity,
			}, "")

			// Expect an error since the client is not implemented.
			Expect(err).To(HaveOccurred())
			Expect(l).To(BeNil())

			// But we should be able to check the request...
			url := fakeREST.Req.URL
			logrus.Debug("URL: ", url)
			Expect(url.Path).To(Equal("/apis/blockaffinities"))
			Expect(url.Query().Get("fieldSelector")).To(Equal("metadata.name=foo"))
		})

		It("should auto-label v3 BlockAffinity on create", func() {
			val := &apiv3.BlockAffinity{
				TypeMeta: metav1.TypeMeta{
					Kind:       apiv3.KindBlockAffinity,
					APIVersion: apiv3.GroupVersionCurrent,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:   "ba1",
					Labels: map[string]string{},
				},
				Spec: apiv3.BlockAffinitySpec{
					State:   apiv3.StateConfirmed,
					Node:    "v3-host",
					Type:    string(ipam.AffinityTypeHost),
					CIDR:    "10.20.0.0/24",
					Deleted: false,
				},
			}

			kvp := &model.KVPair{
				Key:   model.ResourceKey{Name: "ba1", Kind: apiv3.KindBlockAffinity},
				Value: val,
			}

			// We expect an error since fake REST doesn't return a response, but the request will be captured.
			_, _ = client.Create(context.TODO(), kvp)

			// Inspect the request body for labels.
			req := fakeREST.Req
			Expect(req).ToNot(BeNil())
			Expect(req.URL.Path).To(Equal("/apis/blockaffinities"))
			bodyBytes, err := io.ReadAll(req.Body)
			Expect(err).NotTo(HaveOccurred())

			// The posted object should be in the backend libapiv3 format.
			var posted libapiv3.BlockAffinity
			Expect(json.Unmarshal(bodyBytes, &posted)).To(Succeed(), string(bodyBytes))
			Expect(posted.Labels).To(HaveKey(apiv3.LabelHostnameHash))
			Expect(posted.Labels[apiv3.LabelHostnameHash]).NotTo(BeEmpty())
			Expect(posted.Labels).To(HaveKeyWithValue(apiv3.LabelAffinityType, string(ipam.AffinityTypeHost)))
			Expect(posted.Labels).To(HaveKeyWithValue(apiv3.LabelIPVersion, "4"))
		})
	})

	Context("v1.BlockAffinity tests", func() {
		BeforeEach(func() {
			fakeREST = &fake.RESTClient{
				NegotiatedSerializer: serializer.WithoutConversionCodecFactory{CodecFactory: scheme.Codecs},
				GroupVersion: schema.GroupVersion{
					Group:   "crd.projectcalico.org",
					Version: "v1",
				},
				VersionedAPIPath: "/apis",
			}
			client = resources.NewBlockAffinityClientV1(fakeREST, resources.BackingAPIGroupV1)
		})

		It("should list all", func() {
			l, err := client.List(context.TODO(), model.BlockAffinityListOptions{}, "")

			// Expect an error since the client is not implemented.
			Expect(err).To(HaveOccurred())
			Expect(l).To(BeNil())

			// But we should be able to check the request...
			url := fakeREST.Req.URL
			logrus.Debug("URL: ", url)
			Expect(url.Path).To(Equal("/apis/blockaffinities"))
			Expect(url.Query()).NotTo(HaveKey("metadata.name"))
		})

		It("should _not_ use a fieldSelector for a list name match", func() {
			l, err := client.List(context.TODO(), model.BlockAffinityListOptions{
				Host:         "host",
				AffinityType: "",
				IPVersion:    0,
			}, "")

			// Expect an error since the client is not implemented.
			Expect(err).To(HaveOccurred())
			Expect(l).To(BeNil())

			// But we should be able to check the request...
			url := fakeREST.Req.URL
			logrus.Debug("URL: ", url)
			Expect(url.Path).To(Equal("/apis/blockaffinities"))

			// TODO We can't currently use a field selector here but we'd like to!
			//      The name of the resource combines the host and CIDR, so we can't
			//      filter on just the host.  Possible fix: put the host in a label
			//      so we can filter on that.
			Expect(url.Query()).NotTo(HaveKey("metadata.name"))
		})

		It("should auto-label v1 BlockAffinity on create", func() {
			kvp := &model.KVPair{
				Key: model.BlockAffinityKey{
					Host:         "my-host",
					CIDR:         net.MustParseCIDR("192.168.1.0/24"),
					AffinityType: string(ipam.AffinityTypeHost),
				},
				Value: &model.BlockAffinity{State: model.StateConfirmed},
			}

			// We expect an error since fake REST doesn't return a response, but the request will be captured.
			_, _ = client.Create(context.TODO(), kvp)

			// Inspect the request body for labels.
			req := fakeREST.Req
			Expect(req).ToNot(BeNil())
			Expect(req.URL.Path).To(Equal("/apis/blockaffinities"))
			bodyBytes, err := io.ReadAll(req.Body)
			Expect(err).NotTo(HaveOccurred())

			var posted libapiv3.BlockAffinity
			Expect(json.Unmarshal(bodyBytes, &posted)).To(Succeed(), string(bodyBytes))
			Expect(posted.Labels).To(HaveKey(apiv3.LabelHostnameHash))
			Expect(posted.Labels[apiv3.LabelHostnameHash]).NotTo(BeEmpty())
			Expect(posted.Labels).To(HaveKeyWithValue(apiv3.LabelAffinityType, string(ipam.AffinityTypeHost)))
			Expect(posted.Labels).To(HaveKeyWithValue(apiv3.LabelIPVersion, "4"))
		})
	})
})
