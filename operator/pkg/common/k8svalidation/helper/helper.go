// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.
/*
Copyright 2014 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

The contents of this file are mostly copied, with minor modifications, from:
https://github.com/kubernetes/kubernetes/blob/f38615fb9d1188934213633ff92d523259ae8f6a/pkg/apis/core/helper/helpers.go
*/

package helper

import (
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation"

	core "k8s.io/api/core/v1"
)

// IsHugePageResourceName returns true if the resource name has the huge page
// resource prefix.
func IsHugePageResourceName(name core.ResourceName) bool {
	return strings.HasPrefix(string(name), core.ResourceHugePagesPrefix)
}

// IsQuotaHugePageResourceName returns true if the resource name has the quota
// related huge page resource prefix.
func IsQuotaHugePageResourceName(name core.ResourceName) bool {
	return strings.HasPrefix(string(name), core.ResourceHugePagesPrefix) || strings.HasPrefix(string(name), core.ResourceRequestsHugePagesPrefix)
}

// Semantic can do semantic deep equality checks for core objects.
// Example: apiequality.Semantic.DeepEqual(aPod, aPodWithNonNilButEmptyMaps) == true
var Semantic = conversion.EqualitiesOrDie(
	func(a, b resource.Quantity) bool {
		// Ignore formatting, only care that numeric value stayed the same.
		// Uninitialized quantities are equivalent to 0 quantities.
		return a.Cmp(b) == 0
	},
	func(a, b metav1.MicroTime) bool {
		return a.Equal(&b)
	},
	func(a, b metav1.Time) bool {
		return a.Equal(&b)
	},
	func(a, b labels.Selector) bool {
		return a.String() == b.String()
	},
	func(a, b fields.Selector) bool {
		return a.String() == b.String()
	},
)

var standardContainerResources = sets.New[string](
	string(core.ResourceCPU),
	string(core.ResourceMemory),
	string(core.ResourceEphemeralStorage),
)

// IsStandardContainerResourceName returns true if the container can make a resource request
// for the specified resource
func IsStandardContainerResourceName(str string) bool {
	return standardContainerResources.Has(str) || IsHugePageResourceName(core.ResourceName(str))
}

// IsExtendedResourceName returns true if:
// 1. the resource name is not in the default namespace;
// 2. resource name does not have "requests." prefix,
// to avoid confusion with the convention in quota
// 3. it satisfies the rules in IsQualifiedName() after converted into quota resource name
func IsExtendedResourceName(name core.ResourceName) bool {
	if IsNativeResource(name) || strings.HasPrefix(string(name), core.DefaultResourceRequestsPrefix) {
		return false
	}
	// Ensure it satisfies the rules in IsQualifiedName() after converted into quota resource name
	nameForQuota := fmt.Sprintf("%s%s", core.DefaultResourceRequestsPrefix, string(name))
	if errs := validation.IsQualifiedName(string(nameForQuota)); len(errs) != 0 {
		return false
	}
	return true
}

// IsNativeResource returns true if the resource name is in the
// *kubernetes.io/ namespace. Partially-qualified (unprefixed) names are
// implicitly in the kubernetes.io/ namespace.
func IsNativeResource(name core.ResourceName) bool {
	return !strings.Contains(string(name), "/") ||
		strings.Contains(string(name), core.ResourceDefaultNamespacePrefix)
}

var standardResources = sets.New[string](
	string(core.ResourceCPU),
	string(core.ResourceMemory),
	string(core.ResourceEphemeralStorage),
	string(core.ResourceRequestsCPU),
	string(core.ResourceRequestsMemory),
	string(core.ResourceRequestsEphemeralStorage),
	string(core.ResourceLimitsCPU),
	string(core.ResourceLimitsMemory),
	string(core.ResourceLimitsEphemeralStorage),
	string(core.ResourcePods),
	string(core.ResourceQuotas),
	string(core.ResourceServices),
	string(core.ResourceReplicationControllers),
	string(core.ResourceSecrets),
	string(core.ResourceConfigMaps),
	string(core.ResourcePersistentVolumeClaims),
	string(core.ResourceStorage),
	string(core.ResourceRequestsStorage),
	string(core.ResourceServicesNodePorts),
	string(core.ResourceServicesLoadBalancers),
)

// IsStandardResourceName returns true if the resource is known to the system
func IsStandardResourceName(str string) bool {
	return standardResources.Has(str) || IsQuotaHugePageResourceName(core.ResourceName(str))
}

var integerResources = sets.New[string](
	string(core.ResourcePods),
	string(core.ResourceQuotas),
	string(core.ResourceServices),
	string(core.ResourceReplicationControllers),
	string(core.ResourceSecrets),
	string(core.ResourceConfigMaps),
	string(core.ResourcePersistentVolumeClaims),
	string(core.ResourceServicesNodePorts),
	string(core.ResourceServicesLoadBalancers),
)

// IsIntegerResourceName returns true if the resource is measured in integer values
func IsIntegerResourceName(str string) bool {
	return integerResources.Has(str) || IsExtendedResourceName(core.ResourceName(str))
}
