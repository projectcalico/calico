// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
)

var (
	CommonName               = "common-name"
	URISAN                   = "uri-san"
	TyphaCommonName          = "typha-server"
	FelixCommonName          = "typha-client"
	NodePriorityClassName    = "system-node-critical"
	ClusterPriorityClassName = "system-cluster-critical"
)

// A Renderer is capable of generating components to be installed on the cluster.
type Renderer interface {
	Render() []Component
}

func SetTestLogger(l logr.Logger) {
	log = l
}

func SetNodeCriticalPod(t *corev1.PodTemplateSpec) {
	t.Spec.PriorityClassName = NodePriorityClassName
}

func SetClusterCriticalPod(t *corev1.PodTemplateSpec) {
	t.Spec.PriorityClassName = ClusterPriorityClassName
}
