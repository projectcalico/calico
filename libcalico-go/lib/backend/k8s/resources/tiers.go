// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/client-go/rest"

	cresources "github.com/projectcalico/calico/libcalico-go/lib/resources"
)

const (
	TierResourceName = "Tiers"
)

func NewTierClient(r rest.Interface, group BackingAPIGroup) K8sResourceClient {
	return &customResourceClient{
		restClient:       r,
		resource:         TierResourceName,
		k8sResourceType:  reflect.TypeOf(apiv3.Tier{}),
		k8sListType:      reflect.TypeOf(apiv3.TierList{}),
		kind:             apiv3.KindTier,
		versionconverter: tierDefaulter{},
		apiGroup:         group,
	}
}

// tierDefaulter implements VersionConverter interface.
type tierDefaulter struct{}

// ConvertFromK8s sets defaults on the Tier when reading it from the Kubernetes API.
func (c tierDefaulter) ConvertFromK8s(inRes Resource) (Resource, error) {
	tier, ok := inRes.(*apiv3.Tier)
	if !ok {
		return nil, fmt.Errorf("invalid type conversion")
	}
	cresources.DefaultTierFields(tier)
	return tier, nil
}
