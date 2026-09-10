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

// Package v1 contains the DatastoreMigration API types.
//
// +kubebuilder:object:generate=true
// +groupName=migration.projectcalico.org
// +versionName=v1
package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// SchemeGroupVersion is the group version used to register the migration API objects.
var SchemeGroupVersion = schema.GroupVersion{Group: Group, Version: Version}

var (
	// SchemeBuilder collects functions to add types to the scheme.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme applies all stored SchemeBuilder functions to a scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func addKnownTypes(scheme *runtime.Scheme) error {
	return AddToSchemeForVersion(scheme, Version)
}

// AddToSchemeForVersion registers the types under the given migration group
// version. v1beta1 is wire-identical to v1.
func AddToSchemeForVersion(scheme *runtime.Scheme, version string) error {
	gv := schema.GroupVersion{Group: Group, Version: version}
	scheme.AddKnownTypes(gv,
		&DatastoreMigration{},
		&DatastoreMigrationList{},
	)
	metav1.AddToGroupVersion(scheme, gv)
	return nil
}
