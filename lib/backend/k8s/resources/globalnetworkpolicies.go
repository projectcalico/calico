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

package resources

import (
	"reflect"

	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/custom"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/converter"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	GlobalNetworkPolicyResourceName = "GlobalNetworkPolicies"
	GlobalNetworkPolicyCRDName      = "globalnetworkpolicies.crd.projectcalico.org"
)

func NewGlobalNetworkPolicyClient(c *kubernetes.Clientset, r *rest.RESTClient) K8sResourceClient {
	return &customK8sResourceClient{
		clientSet:       c,
		restClient:      r,
		name:            GlobalNetworkPolicyCRDName,
		resource:        GlobalNetworkPolicyResourceName,
		description:     "Calico Global Network Policies",
		k8sResourceType: reflect.TypeOf(custom.GlobalNetworkPolicy{}),
		k8sListType:     reflect.TypeOf(custom.GlobalNetworkPolicyList{}),
		converter:       GlobalNetworkPolicyConverter{},
	}
}

// GlobalNetworkPolicyConverter implements the K8sResourceConverter interface.
type GlobalNetworkPolicyConverter struct {
	// Since the Spec is identical to the Calico API Spec, we use the
	// API converter to convert to and from the model representation.
	converter.PolicyConverter
}

func (_ GlobalNetworkPolicyConverter) ListInterfaceToKey(l model.ListInterface) model.Key {
	pl := l.(model.PolicyListOptions)
	if pl.Name != "" {
		return model.PolicyKey{Name: pl.Name}
	}
	return nil
}

func (_ GlobalNetworkPolicyConverter) KeyToName(k model.Key) (string, error) {
	return k.(model.PolicyKey).Name, nil
}

func (_ GlobalNetworkPolicyConverter) NameToKey(name string) (model.Key, error) {
	return model.PolicyKey{
		Name: name,
	}, nil
}

func (c GlobalNetworkPolicyConverter) ToKVPair(r CustomK8sResource) (*model.KVPair, error) {
	// Since we are using the Calico API Spec definition to store the Calico
	// Policy, use the client conversion helper to convert between KV and API.
	t := r.(*custom.GlobalNetworkPolicy)
	policy := api.Policy{
		Metadata: api.PolicyMetadata{
			Name: t.Metadata.Name,
		},
		Spec: t.Spec,
	}
	kvp, err := c.ConvertAPIToKVPair(policy)
	kvp.Revision = t.Metadata.ResourceVersion

	return kvp, err
}

func (c GlobalNetworkPolicyConverter) FromKVPair(kvp *model.KVPair) (CustomK8sResource, error) {
	r, err := c.ConvertKVPairToAPI(kvp)
	if err != nil {
		return nil, err
	}

	crdName, err := c.KeyToName(kvp.Key)
	if err != nil {
		return nil, err
	}

	crd := custom.GlobalNetworkPolicy{
		Metadata: metav1.ObjectMeta{
			Name: crdName,
		},
		Spec: r.(*api.Policy).Spec,
	}
	if kvp.Revision != nil {
		crd.Metadata.ResourceVersion = kvp.Revision.(string)
	}
	return &crd, nil
}
