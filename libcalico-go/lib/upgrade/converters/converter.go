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

package converters

import (
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/projectcalico/calico/libcalico-go/lib/apis/v1/unversioned"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// Resource is implemented by all Calico resources.
type Resource interface {
	runtime.Object
	v1.ObjectMetaAccessor
}

type Converter interface {
	// APIV1ToBackendV1 converts unversioned resource (v1 API) to v1 KVPair.
	APIV1ToBackendV1(unversioned.Resource) (*model.KVPair, error)

	// BackendV1ToAPIV3 converts v1 KVPair to v3 resource (v3 API)
	BackendV1ToAPIV3(*model.KVPair) (Resource, error)
}
