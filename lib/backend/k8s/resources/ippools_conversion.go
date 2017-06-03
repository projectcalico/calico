// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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
	"encoding/json"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/thirdparty"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ThirdPartyToIPPool takes a Kubernetes ThirdPartyResource representation
// of a Calico IP Pool and returns the equivalent IPPool object.
func ThirdPartyToIPPool(t *thirdparty.IpPool) *model.KVPair {
	v := model.IPPool{}
	err := json.Unmarshal([]byte(t.Spec.Value), &v)
	if err != nil {
		log.Fatalf("Error unmarshalling IPPool value: %s", err)
	}
	return &model.KVPair{
		Key:      model.IPPoolKey{CIDR: v.CIDR},
		Value:    &v,
		Revision: t.Metadata.ResourceVersion,
	}
}

// IPPoolToThirdParty takes a Calico IP Pool and returns the equivalent
// ThirdPartyResource representation.
func IPPoolToThirdParty(kvp *model.KVPair) *thirdparty.IpPool {
	v, err := json.Marshal(kvp.Value.(*model.IPPool))
	if err != nil {
		log.Fatalf("Error marshalling IPPool value: %s", err)
	}

	tpr := thirdparty.IpPool{
		Metadata: metav1.ObjectMeta{
			// Names in Kubernetes must be lower-case.
			Name: ipPoolTprName(kvp.Key.(model.IPPoolKey)),
		},
		Spec: thirdparty.IpPoolSpec{
			Value: string(v),
		},
	}
	if kvp.Revision != nil {
		tpr.Metadata.ResourceVersion = kvp.Revision.(string)
	}
	return &tpr
}

// ipPoolTprName converts the given IPPool key into a unique third party resource
// name.
func ipPoolTprName(key model.IPPoolKey) string {
	name := strings.Replace(key.CIDR.String(), ".", "-", 3)
	name = strings.Replace(name, ":", "-", 7)
	name = strings.Replace(name, "/", "-", 1)
	return name
}
