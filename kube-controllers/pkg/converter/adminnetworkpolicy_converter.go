// Copyright (c) 2024 Tigera, Inc. All rights reserved.
//
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

package converter

import (
	"errors"
	"fmt"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	adminpolicy "sigs.k8s.io/network-policy-api/apis/v1alpha1"
)

type adminNetworkPolicyConverter struct {
}

// NewAdminNetworkPolicyConverter Constructor for adminNetworkPolicyConverter
func NewAdminNetworkPolicyConverter() Converter {
	return &adminNetworkPolicyConverter{}
}

// Convert takes a Kubernetes AdminNetworkPolicy and returns a Calico api.GlobalNetworkPolicy representation.
func (p *adminNetworkPolicyConverter) Convert(k8sObj interface{}) (interface{}, error) {
	anp, ok := k8sObj.(*adminpolicy.AdminNetworkPolicy)

	if !ok {
		tombstone, ok := k8sObj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return nil, fmt.Errorf("couldn't get object from tombstone %+v", k8sObj)
		}
		anp, ok = tombstone.Obj.(*adminpolicy.AdminNetworkPolicy)
		if !ok {
			return nil, fmt.Errorf("tombstone contained object that is not an  AdminNetworkPolicy %+v", k8sObj)
		}
	}

	c := conversion.NewConverter()
	kvp, err := c.K8sAdminNetworkPolicyToCalico(anp)
	// Silently ignore rule conversion errors. We don't expect any conversion errors
	// since the data given to us here is validated by the Kubernetes API. The conversion
	// code ignores any rules that it cannot parse, and we will pass the valid ones to Felix.
	var e *cerrors.ErrorAdminPolicyConversion
	if err != nil && !errors.As(err, &e) {
		return nil, err
	}
	gnp := kvp.Value.(*api.GlobalNetworkPolicy)

	// Isolate the metadata fields that we care about. ResourceVersion, CreationTimeStamp, etc are
	// not relevant so we ignore them. This prevents unnecessary updates.
	gnp.ObjectMeta = metav1.ObjectMeta{Name: gnp.Name}

	return *gnp, err
}

// GetKey returns name of the Global Network Policy as its key. For GNPs
// backed by Kubernetes namespaces and managed by this controller, the name
// is of format `kanp.adminetworkpolicy.name`.
func (p *adminNetworkPolicyConverter) GetKey(obj interface{}) string {
	policy := obj.(api.GlobalNetworkPolicy)
	return policy.Name
}

func (p *adminNetworkPolicyConverter) DeleteArgsFromKey(key string) (string, string) {
	// Not namespaced, so just return the key, which is the admin network policy name.
	return "", key
}
