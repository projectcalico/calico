// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package client

import (
	"testing"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/runtime"

	v1scheme "github.com/projectcalico/calico/libcalico-go/lib/apis/crd.projectcalico.org/v1/scheme"
)

// The datastore client has to send each Calico kind it uses to the crd.projectcalico.org/v1 CRD,
// never to the aggregated projectcalico.org/v3 group, or it fails along with calico-apiserver.
func TestDatastoreSchemeUsesCRDGroup(t *testing.T) {
	RegisterTestingT(t)

	datastore, err := newSchemeWithCalico(v1scheme.AddCalicoResourcesToScheme)
	Expect(err).NotTo(HaveOccurred())
	aggregated, err := newScheme()
	Expect(err).NotTo(HaveOccurred())

	kinds := []runtime.Object{
		&v3.BGPConfiguration{},
		&v3.BGPPeer{},
		&v3.CalicoNodeStatus{},
		&v3.FelixConfiguration{},
		&v3.IPPool{},
	}
	for _, obj := range kinds {
		gvks, _, err := datastore.ObjectKinds(obj)
		Expect(err).NotTo(HaveOccurred(), "%T missing from the datastore scheme", obj)
		Expect(gvks).To(HaveLen(1), "%T registered under more than one group", obj)
		Expect(gvks[0].GroupVersion().String()).To(Equal(v1scheme.GroupVersion), "%T in the datastore scheme", obj)

		gvks, _, err = aggregated.ObjectKinds(obj)
		Expect(err).NotTo(HaveOccurred(), "%T missing from the default scheme", obj)
		Expect(gvks[0].Group).To(Equal(v3.GroupName), "%T in the default scheme", obj)
	}
}
