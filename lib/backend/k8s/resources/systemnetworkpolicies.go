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
	"fmt"
	"reflect"
	"strings"

	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/thirdparty"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/converter"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	SystemNetworkPolicyResourceName = "systemnetworkpolicies"
	SystemNetworkPolicyTPRName      = "system-network-policy.alpha.projectcalico.org"
	SystemNetworkPolicyNamePrefix   = "snp.projectcalico.org/"
)

func NewSystemNetworkPolicyClient(c *kubernetes.Clientset, r *rest.RESTClient) K8sResourceClient {
	return &customK8sResourceClient{
		clientSet:       c,
		restClient:      r,
		name:            SystemNetworkPolicyTPRName,
		resource:        SystemNetworkPolicyResourceName,
		description:     "Calico System Network Policies",
		k8sResourceType: reflect.TypeOf(thirdparty.SystemNetworkPolicy{}),
		k8sListType:     reflect.TypeOf(thirdparty.SystemNetworkPolicyList{}),
		converter:       SystemNetworkPolicyConverter{},
	}
}

// SystemNetworkPolicyConverter implements the K8sResourceConverter interface.
type SystemNetworkPolicyConverter struct {
	// Since the Spec is identical to the Calico API Spec, we use the
	// API converter to convert to and from the model representation.
	converter.PolicyConverter
}

func (_ SystemNetworkPolicyConverter) ListInterfaceToKey(l model.ListInterface) model.Key {
	pl := l.(model.PolicyListOptions)
	if pl.Name != "" {
		return model.PolicyKey{Name: pl.Name}
	}
	return nil
}

func (_ SystemNetworkPolicyConverter) KeyToName(k model.Key) (string, error) {
	// The name should be policed before we get here.
	pk := k.(model.PolicyKey)
	if !strings.HasPrefix(pk.Name, SystemNetworkPolicyNamePrefix) {
		return "", fmt.Errorf("System Network Policy name %s is not correctly namespaced", pk.Name)
	}
	// Trim the namespace and ensure lowercase.
	return strings.ToLower(strings.TrimPrefix(pk.Name, SystemNetworkPolicyNamePrefix)), nil
}

func (_ SystemNetworkPolicyConverter) NameToKey(name string) (model.Key, error) {
	policyName := fmt.Sprintf("%s%s", SystemNetworkPolicyNamePrefix, name)
	return model.PolicyKey{
		Name: policyName,
	}, nil
}

func (c SystemNetworkPolicyConverter) ToKVPair(r CustomK8sResource) (*model.KVPair, error) {
	// Since we are using the Calico API Spec definition to store the Calico
	// Policy, use the client conversion helper to convert between KV and API.
	t := r.(*thirdparty.SystemNetworkPolicy)
	policyName := fmt.Sprintf("%s%s", SystemNetworkPolicyNamePrefix, t.Metadata.Name)
	policy := api.Policy{
		Metadata: api.PolicyMetadata{
			Name: policyName,
		},
		Spec: t.Spec,
	}
	kvp, err := c.ConvertAPIToKVPair(policy)
	kvp.Revision = t.Metadata.ResourceVersion

	return kvp, err
}

func (c SystemNetworkPolicyConverter) FromKVPair(kvp *model.KVPair) (CustomK8sResource, error) {
	r, err := c.ConvertKVPairToAPI(kvp)
	if err != nil {
		return nil, err
	}

	tprName, err := c.KeyToName(kvp.Key)
	if err != nil {
		return nil, err
	}

	tpr := thirdparty.SystemNetworkPolicy{
		Metadata: metav1.ObjectMeta{
			Name: tprName,
		},
		Spec: r.(*api.Policy).Spec,
	}
	if kvp.Revision != nil {
		tpr.Metadata.ResourceVersion = kvp.Revision.(string)
	}
	return &tpr, nil
}
