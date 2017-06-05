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
	"strings"

	log "github.com/Sirupsen/logrus"

	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/thirdparty"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/converter"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ThirdPartyToSystemNetworkPolicy takes a Kubernetes ThirdPartyResource representation
// of a Calico Policy and returns the equivalent SystemNetworkPolicy object.
func ThirdPartyToSystemNetworkPolicy(t *thirdparty.SystemNetworkPolicy) *model.KVPair {

	// Since we are using the Calico API Spec definition to store the Calico
	// Policy, use the client conversion helper to convert between KV and API.
	policyName := fmt.Sprintf("%s%s", SystemNetworkPolicyNamePrefix, t.Metadata.Name)
	r := api.Policy{
		Metadata: api.PolicyMetadata{
			Name: policyName,
		},
		Spec: t.Spec,
	}
	kvp := converter.PolicyConverter{}.ConvertAPIToKVPair(r)
	kvp.Revision = t.Metadata.ResourceVersion

	return kvp
}

// SystemNetworkPolicyToThirdParty takes a Calico Policy and returns the equivalent
// ThirdPartyResource representation.
func SystemNetworkPolicyToThirdParty(kvp *model.KVPair) *thirdparty.SystemNetworkPolicy {
	r := converter.PolicyConverter{}.ConvertKVPairToAPI(kvp)
	tprName := systemNetworkPolicyTPRName(kvp.Key)
	tpr := thirdparty.SystemNetworkPolicy{
		Metadata: metav1.ObjectMeta{
			Name: tprName,
		},
		Spec: r.(*api.Policy).Spec,
	}
	if kvp.Revision != nil {
		tpr.Metadata.ResourceVersion = kvp.Revision.(string)
	}
	return &tpr
}

// systemNetworkPolicyTPRName converts a Policy (specifically a System Network Policy)
// name to a TPR name.
func systemNetworkPolicyTPRName(key model.Key) string {
	// The name should be policed before we get here.
	pk := key.(model.PolicyKey)
	if !strings.HasPrefix(pk.Name, SystemNetworkPolicyNamePrefix) {
		log.WithField("Key", key).Fatal("System Network Policy name is not correctly namespaced")
	}
	// Trim the namespace and ensure lowercase.
	return strings.ToLower(strings.TrimPrefix(pk.Name, SystemNetworkPolicyNamePrefix))
}
