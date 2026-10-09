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

// Package apigroup tracks which Calico API group the operator should configure
// on the workloads it manages. The value is set once at startup (or when a
// datastore migration completes) and read by the component handler to inject
// the CALICO_API_GROUP env var into all workload containers.
package apigroup

import (
	"sync"

	corev1 "k8s.io/api/core/v1"
)

// APIGroup identifies which Calico CRD API group to use.
type APIGroup int

const (
	// Unknown means the API group hasn't been determined yet.
	Unknown APIGroup = iota
	// V1 uses crd.projectcalico.org/v1 (legacy, via aggregated API server).
	V1
	// V3 uses projectcalico.org/v3 (native CRDs, no API server).
	V3
)

const (
	envVarName = "CALICO_API_GROUP"
	v3Value    = "projectcalico.org/v3"
)

var (
	mu      sync.RWMutex
	current APIGroup
	envVars []corev1.EnvVar
)

// Set records the active API group. If V3, subsequent calls to EnvVars will
// return a CALICO_API_GROUP env var for injection into workload containers.
func Set(g APIGroup) {
	mu.Lock()
	defer mu.Unlock()
	current = g
	if g == V3 {
		envVars = []corev1.EnvVar{{Name: envVarName, Value: v3Value}}
	} else {
		envVars = nil
	}
}

// Get returns the current API group.
func Get() APIGroup {
	mu.RLock()
	defer mu.RUnlock()
	return current
}

// EnvVars returns the env vars to inject into workload containers, or nil if
// no explicit API group has been configured.
func EnvVars() []corev1.EnvVar {
	mu.RLock()
	defer mu.RUnlock()
	return envVars
}
