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

	"github.com/onsi/gomega"
	operatorv1 "github.com/tigera/operator/api/v1"
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

// InstallationConfig returns the operator's effective installation config, published on the
// status. Nil if the cluster isn't operator managed.
func InstallationConfig(cli ctrlclient.Client) *operatorv1.InstallationSpec {
	installation := GetInstallation(cli)
	if installation == nil {
		return nil
	}
	return installation.Status.Computed
}

// UsesCalicoIPAM reports whether the cluster uses Calico IPAM. If the operator
// Installation resource is available, it checks the configured IPAM type.
// Returns true if Calico IPAM is in use or if the IPAM type cannot be determined
// (e.g., on manifest-based installs without an Installation resource).
func UsesCalicoIPAM(cli ctrlclient.Client) bool {
	config := InstallationConfig(cli)
	if config != nil &&
		config.CNI != nil &&
		config.CNI.IPAM != nil &&
		config.CNI.IPAM.Type != operatorv1.IPAMPluginCalico {
		return false
	}
	return true
}

// ExpectBGPEnabled asserts that the cluster was installed by the operator with BGP enabled.
func ExpectBGPEnabled(cli ctrlclient.Client) {
	config := InstallationConfig(cli)
	gomega.ExpectWithOffset(1, config).NotTo(gomega.BeNil(), "No computed configuration on the Installation; is this cluster operator managed?")
	gomega.ExpectWithOffset(1, config.CalicoNetwork).NotTo(gomega.BeNil(), "CalicoNetwork is not configured in the Installation")
	gomega.ExpectWithOffset(1, config.CalicoNetwork.BGP).NotTo(gomega.BeNil(), "BGP is not enabled in the cluster")
	gomega.ExpectWithOffset(1, *config.CalicoNetwork.BGP).To(gomega.Equal(operatorv1.BGPEnabled), "BGP is not enabled in the cluster")
}
