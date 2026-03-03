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

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	operatorv1 "github.com/tigera/operator/api/v1"
	"k8s.io/apimachinery/pkg/types"
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

// GetLinuxDataplane detects the active Linux dataplane by inspecting cluster resources.
// It first checks the operator Installation resource, then falls back to the default
// FelixConfiguration. Returns operatorv1.LinuxDataplaneIptables if detection fails.
func GetLinuxDataplane(cli ctrlclient.Client) operatorv1.LinuxDataplaneOption {
	// Try the Installation resource first (operator-managed installs).
	installation := GetInstallation(cli)
	if installation != nil &&
		installation.Spec.CalicoNetwork != nil &&
		installation.Spec.CalicoNetwork.LinuxDataplane != nil {
		dp := *installation.Spec.CalicoNetwork.LinuxDataplane
		logrus.Infof("Detected Linux dataplane from Installation: %s", dp)
		return dp
	}

	// Fall back to the default FelixConfiguration (manifest-based installs).
	felixConfig := v3.NewFelixConfiguration()
	err := cli.Get(context.Background(), types.NamespacedName{Name: "default"}, felixConfig)
	if err == nil {
		if felixConfig.Spec.BPFEnabled != nil && *felixConfig.Spec.BPFEnabled {
			logrus.Info("Detected Linux dataplane from FelixConfiguration: BPF")
			return operatorv1.LinuxDataplaneBPF
		}
		if felixConfig.Spec.NFTablesMode != nil && *felixConfig.Spec.NFTablesMode == v3.NFTablesModeEnabled {
			logrus.Info("Detected Linux dataplane from FelixConfiguration: Nftables")
			return operatorv1.LinuxDataplaneNftables
		}
		logrus.Info("Detected Linux dataplane from FelixConfiguration: Iptables (default)")
		return operatorv1.LinuxDataplaneIptables
	}

	logrus.WithError(err).Info("Could not detect Linux dataplane, defaulting to Iptables")
	return operatorv1.LinuxDataplaneIptables
}

// UsesCalicoIPAM reports whether the cluster uses Calico IPAM. If the operator
// Installation resource is available, it checks the configured IPAM type.
// Returns true if Calico IPAM is in use or if the IPAM type cannot be determined
// (e.g., on manifest-based installs without an Installation resource).
func UsesCalicoIPAM(cli ctrlclient.Client) bool {
	installation := GetInstallation(cli)
	if installation != nil &&
		installation.Spec.CNI != nil &&
		installation.Spec.CNI.IPAM != nil &&
		installation.Spec.CNI.IPAM.Type != operatorv1.IPAMPluginCalico {
		return false
	}
	return true
}
