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

package utils

import (
	"context"

	operatorv1 "github.com/tigera/operator/api/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// GetInstallation returns the operator Installation resource if available.
// Returns nil if the Installation resource cannot be retrieved (e.g., on
// manifest-based installs where the operator CRD may not exist).
func GetInstallation(cli ctrlclient.Client) *operatorv1.Installation {
	installation := &operatorv1.Installation{}
	err := cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, installation)
	if err != nil {
		return nil
	}
	return installation
}

// RequireBGPEnabled fails the test unless the operator installed the cluster with BGP
// networking enabled. Lanes whose clusters run in another networking mode should exclude
// the RequiresBGP label instead of running these tests.
func RequireBGPEnabled(cli ctrlclient.Client) {
	installation := &operatorv1.Installation{}
	if err := cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, installation); err != nil {
		framework.Failf("Error querying the Installation resource: %v", err)
	}
	network := installation.Spec.CalicoNetwork
	if network == nil || network.BGP == nil || *network.BGP != operatorv1.BGPEnabled {
		framework.Failf("BGP is not enabled in this cluster, so the lane should exclude the RequiresBGP label")
	}
}
