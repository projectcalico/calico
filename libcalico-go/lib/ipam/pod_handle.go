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

package ipam

import (
	"regexp"
	"strings"
)

// vmHandleInfix is vmipam.VMHandleInfix, which this package can't import without a cycle.
const vmHandleInfix = ".vmi."

// runtimeContainerID matches the 64-character hex IDs that container runtimes give sandboxes.
var runtimeContainerID = regexp.MustCompile(`^[0-9a-f]{64}$`)

// PodHandle is a pod sandbox's IPAM handle split into the CNI network its addresses were
// assigned on and the sandbox's container ID.
type PodHandle struct {
	Network     string
	ContainerID string
}

// PodHandleID returns the handle that the CNI plugin assigns a pod sandbox's addresses
// under. See design/ipam/ipam-cni.md for the handle forms and who writes them.
func PodHandleID(network, containerID string) string {
	return network + "." + containerID
}

// ParsePodHandleID splits a pod sandbox's handle assigned on the given network. It rejects
// workload, VM and load balancer handles, which use other forms. Any container ID without
// a dot is accepted, so it suits a caller that knows the network, such as the CNI plugin.
func ParsePodHandleID(handleID, network string) (PodHandle, bool) {
	containerID, ok := strings.CutPrefix(trimMigrationSuffix(handleID), network+".")
	if !ok {
		return PodHandle{}, false
	}

	// A dot left in the container ID means this is not a sandbox handle: pre-v3 handles
	// name the workload (k8s-pod-network.default.mypod), VM handles name the VMI
	// (k8s-pod-network.vmi.default.vm1).
	if containerID == "" || strings.Contains(containerID, ".") {
		return PodHandle{}, false
	}
	return PodHandle{Network: network, ContainerID: containerID}, true
}

// ParsePodHandleIDAnyNetwork splits a pod sandbox's handle without knowing its network, as
// the IPAM GC must. Network names may contain dots, so the container ID is what follows the
// last one, and it must have the runtime's 64-character hex form. That form is what tells a
// sandbox handle from a pre-v3 workload handle ending in a pod name. A hashed VM handle ends
// in the same form, so handles with the VM infix are rejected.
func ParsePodHandleIDAnyNetwork(handleID string) (PodHandle, bool) {
	handleID = trimMigrationSuffix(handleID)
	i := strings.LastIndex(handleID, ".")
	if i <= 0 {
		return PodHandle{}, false
	}

	network, containerID := handleID[:i], handleID[i+1:]
	if !runtimeContainerID.MatchString(containerID) || strings.HasSuffix(network+".", vmHandleInfix) {
		return PodHandle{}, false
	}
	return PodHandle{Network: network, ContainerID: containerID}, true
}

// trimMigrationSuffix drops the trailing carriage return that handles written during the
// host-local migration can carry; see https://github.com/projectcalico/cni-plugin/issues/821.
func trimMigrationSuffix(handleID string) string {
	return strings.Split(handleID, "\r")[0]
}
