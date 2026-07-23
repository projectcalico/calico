// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package migration

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// hasFinalizer returns true if the DatastoreMigration CR has the migration finalizer.
func hasFinalizer(dm *DatastoreMigration) bool {
	for _, f := range dm.Finalizers {
		if f == finalizerName {
			return true
		}
	}
	return false
}

// crdGVR is the GVR for CustomResourceDefinition objects.
var crdGVR = schema.GroupVersionResource{
	Group:    "apiextensions.k8s.io",
	Version:  "v1",
	Resource: "customresourcedefinitions",
}
