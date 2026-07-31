// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nftables

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
	"sigs.k8s.io/knftables"
)

// flowOffloadProbeTable is a throwaway table used only while probing for flowtable offload
// support. It is created and immediately deleted, so it never coexists with the real "calico" table.
const flowOffloadProbeTable = "calico-flowtable-probe"

// DetectFlowOffloadSupported reports whether the running kernel accepts an nftables flowtable.
// Kernels without the nf_flow_table module reject flowtable programming with ENOENT, which would
// otherwise take Felix down when it installs the real flowtable and offload rule. We find out up
// front by adding a device-less flowtable in a throwaway table: the flowtable object needs the
// module regardless of its device set, so this hits the same failure a real flowtable would.
func DetectFlowOffloadSupported(newDataplane NewNftablesDataplaneFn) bool {
	if newDataplane == nil {
		newDataplane = knftables.New
	}

	nft, err := newDataplane(knftables.IPv4Family, flowOffloadProbeTable)
	if err != nil {
		logrus.WithError(err).Warn("Failed to create nftables interface to probe flowtable offload support; assuming unsupported.")
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	prio := knftables.FilterIngressPriority
	tx := nft.NewTransaction()
	tx.Add(&knftables.Table{})
	tx.Add(&knftables.Flowtable{
		Name:     "probe",
		Priority: &prio,
	})
	if err := nft.Run(ctx, tx); err != nil {
		logrus.WithError(err).Debug("Kernel rejected the flowtable probe; nftables flowtable offload is unsupported.")
		return false
	}

	// Deleting the probe table takes the flowtable with it. Best-effort: a leftover empty table is
	// harmless and gets reused on the next probe.
	cleanup := nft.NewTransaction()
	cleanup.Delete(&knftables.Table{})
	if err := nft.Run(ctx, cleanup); err != nil {
		logrus.WithError(err).Warn("Failed to clean up nftables flowtable offload probe table.")
	}

	return true
}
