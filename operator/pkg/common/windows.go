// Copyright (c) 2021-2024 Tigera, Inc. All rights reserved.

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

// GetWindowsNodes returns Windows nodes, optionally filtering the list of nodes
// with the given filter functions.
package common

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
)

const (
	CalicoWindowsUpgradeResourceName = "calico-windows-upgrade"
)

func HasWindowsNodes(c client.Client) (bool, error) {
	nodes := corev1.NodeList{}
	err := c.List(context.Background(), &nodes, client.MatchingLabels{"kubernetes.io/os": "windows"})
	if err != nil {
		return false, err
	}

	return len(nodes.Items) > 0, nil
}

// WindowsEnabled returns true if the given Installation enables Windows, false otherwise.
func WindowsEnabled(installation operatorv1.InstallationSpec) bool {
	return installation.CalicoNetwork != nil &&
		installation.CalicoNetwork.WindowsDataplane != nil &&
		*installation.CalicoNetwork.WindowsDataplane != operatorv1.WindowsDataplaneDisabled
}
