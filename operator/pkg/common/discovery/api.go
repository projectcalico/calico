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

package discovery

import (
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// trackedGroupKinds enumerates the Kubernetes API kinds the operator wants to know served
// versions for. Add an entry here when a controller needs to branch on whether (or which version
// of) an API is available.
var trackedGroupKinds = []schema.GroupKind{
	{Group: "admissionregistration.k8s.io", Kind: "MutatingAdmissionPolicy"},
	{Group: "admissionregistration.k8s.io", Kind: "ValidatingAdmissionPolicy"},
}

// APIDiscovery is a snapshot of which API versions a cluster serves for the set of GroupKinds the
// operator cares about. Lookups are pure map reads; no API calls are made after construction.
type APIDiscovery struct {
	versions map[schema.GroupKind]string
}

// DiscoverAPIs consults the supplied RESTMapper for each tracked GroupKind and records the
// preferred served version. GroupKinds not served by the cluster (or unknown to the RESTMapper)
// map to the empty string. Only GroupKinds listed in trackedGroupKinds are queried.
func DiscoverAPIs(mapper meta.RESTMapper) *APIDiscovery {
	d := &APIDiscovery{versions: map[schema.GroupKind]string{}}
	for _, gk := range trackedGroupKinds {
		// RESTMappings returns mappings sorted by the group's preferred-version order from
		// discovery — for a GA API like v1+v1beta1, v1 comes first.
		mappings, err := mapper.RESTMappings(gk)
		if err != nil || len(mappings) == 0 {
			continue
		}
		d.versions[gk] = mappings[0].GroupVersionKind.Version
	}
	return d
}

// ServedVersion returns the preferred served version for the given GroupKind, or "" if the kind
// is not served by the cluster (or is not in the tracked set).
func (d *APIDiscovery) ServedVersion(group, kind string) string {
	if d == nil {
		return ""
	}
	return d.versions[schema.GroupKind{Group: group, Kind: kind}]
}

// NewStaticAPIDiscovery constructs an APIDiscovery from an explicit version map. Intended for tests.
func NewStaticAPIDiscovery(versions map[schema.GroupKind]string) *APIDiscovery {
	cp := make(map[schema.GroupKind]string, len(versions))
	for k, v := range versions {
		cp[k] = v
	}
	return &APIDiscovery{versions: cp}
}
