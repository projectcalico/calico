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

package utils

import (
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ComponentHandlerExtension is what an extension knows about the kinds it installs
// that the core operator cannot infer, because it does not compile against those
// types. Each method is named for the componentHandler function that calls it, and
// reports false or nil for a kind the extension does not own.
type ComponentHandlerExtension interface {
	// MergeState merges the current object into the desired one, for a kind whose
	// controller writes fields the operator must not revert.
	MergeState(desired client.Object, current runtime.Object) (client.Object, bool)

	// SkipAddingOwnerReference reports a kind that is garbage collected some other
	// way, so the operator leaves its owner references alone.
	SkipAddingOwnerReference(obj client.Object) bool

	// ModifyPodSpec applies f to every pod spec inside the object.
	ModifyPodSpec(obj client.Object, f func(*v1.PodSpec))

	// Containers returns the containers inside the object. Modifying a container's
	// probes reaches the object, since a probe is a pointer.
	Containers(obj client.Object) []v1.Container

	// EnsureOSSchedulingRestrictions pins the object's pods to an OS, for a kind
	// whose pod template is not a v1.PodTemplateSpec.
	EnsureOSSchedulingRestrictions(obj client.Object, key, value string) bool

	// SetStandardSelectorAndLabels copies the object's own labels onto the pods it
	// creates, for a kind whose pod template is not a v1.PodTemplateSpec.
	SetStandardSelectorAndLabels(obj client.Object) bool
}

// extensionObjectRules is what the running extension registered, or nil for core alone.
var extensionObjectRules ComponentHandlerExtension

// RegisterComponentHandlerExtension declares how the operator handles the kinds an
// extension installs. Call it before the operator starts.
func RegisterComponentHandlerExtension(e ComponentHandlerExtension) {
	extensionObjectRules = e
}
