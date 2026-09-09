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

package datastoremigration

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	GroupName = "migration.projectcalico.org"
	Kind      = "DatastoreMigration"
	ListKind  = "DatastoreMigrationList"
	Resource  = "datastoremigrations"
)

var (
	// GroupVersionV1 is the GA group/version, the storage version from Calico v3.33.
	GroupVersionV1 = schema.GroupVersion{Group: GroupName, Version: "v1"}

	// GroupVersionV1beta1 is the pre-GA group/version, deprecated but still served in v3.33.
	// TODO: remove in v3.34.
	GroupVersionV1beta1 = schema.GroupVersion{Group: GroupName, Version: "v1beta1"}
)
