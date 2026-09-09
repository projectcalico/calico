// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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

package common

import (
	"fmt"
	"strconv"
	"strings"

	"k8s.io/client-go/kubernetes"
)

// VersionInfo contains information about the version of Kubernetes API the cluster is using
// Major and Minor fields map to the v<Major>.<Minor>+ part of the version string
type VersionInfo struct {
	Major int
	Minor int
}

func GetKubernetesVersion(clientset kubernetes.Interface) (*VersionInfo, error) {
	v, err := clientset.Discovery().ServerVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to check k8s version: %v", err)
	}

	major, err := strconv.Atoi(v.Major)
	if err != nil {
		return nil, fmt.Errorf("failed to parse k8s major version: %s", v.Major)
	}

	// filter out a proceeding '+' from the minor version since openshift includes that.
	minor, err := strconv.Atoi(strings.TrimSuffix(v.Minor, "+"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse k8s minor version: %s", v.Minor)
	}

	return &VersionInfo{
		Major: major,
		Minor: minor,
	}, nil
}

// ProvidesCertV1API returns if k8s.io/api/certificates/v1 is supported given the current k8s version
func (v *VersionInfo) ProvidesCertV1API() bool {
	if v != nil && (v.Major > 1 || (v.Major == 1 && v.Minor >= 19)) {
		return true
	}
	return false
}
