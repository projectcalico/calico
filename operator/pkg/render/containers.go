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

package render

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
)

// Container returns the named container in spec, init containers included. The
// returned pointer aliases spec. Use it for containers a component only renders
// under some configurations; for the rest, use MustContainer.
func Container(spec *corev1.PodSpec, name string) (*corev1.Container, bool) {
	for i := range spec.Containers {
		if spec.Containers[i].Name == name {
			return &spec.Containers[i], true
		}
	}
	for i := range spec.InitContainers {
		if spec.InitContainers[i].Name == name {
			return &spec.InitContainers[i], true
		}
	}
	return nil, false
}

// MustContainer returns the named container, panicking if it is absent. A modifier
// asking for a container that is always rendered and not finding one means render
// and the modifier have drifted apart, which no caller can recover from.
func MustContainer(spec *corev1.PodSpec, name string) *corev1.Container {
	c, ok := Container(spec, name)
	if !ok {
		panic(fmt.Sprintf("BUG: no container named %q to modify", name))
	}
	return c
}

// MustContainers returns the named containers, panicking if any is absent.
func MustContainers(spec *corev1.PodSpec, names ...string) []*corev1.Container {
	found := make([]*corev1.Container, 0, len(names))
	for _, name := range names {
		found = append(found, MustContainer(spec, name))
	}
	return found
}
