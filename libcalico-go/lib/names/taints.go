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

package names

const (
	// NetworkReadyTaintKey is the taint Calico uses to keep workloads from scheduling onto a node
	// before its networking is ready. New nodes are tainted via a MutatingAdmissionPolicy; calico-node
	// removes the taint once Felix and BIRD are ready and re-adds it if they fail at runtime.
	NetworkReadyTaintKey = "node.projectcalico.org/network-not-ready"

	// NetworkReadyTaintEnvVar gates the network-ready taint feature. The operator sets it on
	// calico-node and kube-controllers when the feature is enabled in the Installation resource.
	// Both components leave the taint alone unless this is set to "true", so that the feature stays
	// fully opt-in and we never strip a taint we weren't asked to manage.
	NetworkReadyTaintEnvVar = "CALICO_MANAGE_NETWORK_READY_TAINT"
)
