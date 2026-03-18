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

package discovery

import "k8s.io/client-go/discovery"

// IsOperatorManaged returns true if the cluster is managed by the Tigera operator,
// detected by checking whether the operator.tigera.io API group is registered.
func IsOperatorManaged(client discovery.DiscoveryInterface) bool {
	_, err := client.ServerResourcesForGroupVersion("operator.tigera.io/v1")
	return err == nil
}
