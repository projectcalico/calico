// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/client-go/rest"

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
)

// ipamConfigResourceClient returns a customResourceClient for IPAMConfig resources based on the
// specified REST client and whether to use v3 CRDs.
func ipamConfigResourceClient(r rest.Interface, group BackingAPIGroup) customResourceClient {
	resource := IPAMConfigResourceName
	if group == BackingAPIGroupV3 {
		resource = IPAMConfigResourceNameV3
	}

	rc := customResourceClient{
		restClient:      r,
		resource:        resource,
		k8sResourceType: reflect.TypeOf(libapiv3.IPAMConfig{}),
		k8sListType:     reflect.TypeOf(libapiv3.IPAMConfigList{}),
		kind:            v3.KindIPAMConfiguration,
		apiGroup:        group,
	}

	if group == BackingAPIGroupV3 {
		// If this is a v3 resource, then we need to use the v3 API types, as they differ.
		rc.k8sResourceType = reflect.TypeOf(v3.IPAMConfiguration{})
		rc.k8sListType = reflect.TypeOf(v3.IPAMConfigurationList{})
	}
	return rc
}
