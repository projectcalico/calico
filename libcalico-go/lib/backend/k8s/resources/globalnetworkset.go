// Copyright (c) 2018 Tigera, Inc. All rights reserved.

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

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/client-go/rest"
)

const (
	GlobalNetworkSetResourceName = "GlobalNetworkSets"
)

func NewGlobalNetworkSetClient(r rest.Interface, v3 bool) K8sResourceClient {
	return &customResourceClient{
		restClient:      r,
		resource:        GlobalNetworkSetResourceName,
		k8sResourceType: reflect.TypeOf(apiv3.GlobalNetworkSet{}),
		k8sListType:     reflect.TypeOf(apiv3.GlobalNetworkSetList{}),
		kind:            apiv3.KindGlobalNetworkSet,
		noTransform:     v3,
	}
}
