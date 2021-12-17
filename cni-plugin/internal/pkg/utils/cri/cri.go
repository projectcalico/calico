// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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

package cri

import (
	"strings"
)

const (
	PauseContainerNetNS = "none"
)

// IsDockershimV1 checks whether the CNI request is from the
// Dockershim baked into kubelet. In that case, Docker will use either "none" or
// "container:<container ID>" for the netns arg. If the request is from containerd
// then netns will be a hex string.
// We use the netns value to determine whether to use HNS V1 APIs (for Dockershim)
// or HNS V2 APIs (for containerd and other CRI-compliant runtimes).
func IsDockershimV1(netns string) bool {
	return netns == PauseContainerNetNS || strings.HasPrefix(netns, "container:")
}
