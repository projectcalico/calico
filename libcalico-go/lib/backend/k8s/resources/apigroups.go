// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	crdv1 "github.com/projectcalico/calico/libcalico-go/lib/apis/crd.projectcalico.org/v1/scheme"
)

// BackingAPIGroup represents the API group used for Calico CRD backend.
type BackingAPIGroup string

const (
	// BackingAPIGroupV1 represents the use of crd.projectcalico.org/v1 custom resource definitions.
	BackingAPIGroupV1 BackingAPIGroup = crdv1.GroupVersion

	// BackingAPIGroupV3 represents the use of projectcalico.org/v3 custom resource definitions.
	BackingAPIGroupV3 BackingAPIGroup = apiv3.GroupVersionCurrent
)
