// Copyright (c) 2022-2024 Tigera, Inc. All rights reserved.

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

package convert

import (
	corev1 "k8s.io/api/core/v1"
)

func getContainer(spec corev1.PodSpec, name string) *corev1.Container {
	for _, container := range spec.Containers {
		if container.Name == name {
			return &container
		}
	}
	for _, container := range spec.InitContainers {
		if container.Name == name {
			return &container
		}
	}
	return nil
}

func getVolume(spec corev1.PodSpec, name string) *corev1.Volume {
	for _, volume := range spec.Volumes {
		if volume.Name == name {
			return &volume
		}
	}
	return nil
}
