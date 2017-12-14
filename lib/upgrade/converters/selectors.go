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
	"strings"
)

var (
	v1NamespaceSelector = "calico/k8s_ns"
	v3NamespaceSelector = "projectcalico.org/namespace"
)

// convertSelector converts a v1 selector to a v3 selector.
func convertSelector(sel string) string {
	// v1 selectors used calico/k8s_ns, v3 instead uses projectcalico.org/namespace
	return strings.Replace(sel, v1NamespaceSelector, v3NamespaceSelector, -1)
}
