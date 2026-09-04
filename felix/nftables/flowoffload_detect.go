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
// support, so a failed cleanup can't disturb the real "calico" table.
const flowOffloadProbeTable = "calico-flowtable-probe"

// The two probes use different flowtable names because the kernel turns an add of an existing
// flowtable into an update, and pre-5.13 update paths accept the counter flag they reject on add.
const (
	counterProbeFlowtable = "probe-counter"
	plainProbeFlowtable   = "probe"
)

// DetectFlowOffloadSupported reports whether the kernel accepts an nftables flowtable, and whether
// it also accepts the flowtable counter flag.
func DetectFlowOffloadSupported(newDataplane NewNftablesDataplaneFn) (supported bool, counter bool) {
	if newDataplane == nil {
		newDataplane = knftables.New
	}

	nft, err := newDataplane(knftables.IPv4Family, flowOffloadProbeTable)
	if err != nil {
		logrus.WithError(err).Warn("Failed to create nftables interface to probe flowtable offload support; assuming unsupported.")
		return false, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Counters arrived in 5.13, long after flowtables. Probing twice separates a kernel with no
	// flowtables from one with no counters.
	supported = probeFlowtable(ctx, nft, counterProbeFlowtable, true)
	counter = supported
	if !supported {
		supported = probeFlowtable(ctx, nft, plainProbeFlowtable, false)
	}

	if supported {
		// Deleting the probe table takes the flowtable with it. A leftover empty table is harmless.
		cleanup := nft.NewTransaction()
		cleanup.Delete(&knftables.Table{})
		if err := nft.Run(ctx, cleanup); err != nil {
			logrus.WithError(err).Warn("Failed to clean up nftables flowtable offload probe table.")
		}
	}

	return supported, counter
}

// probeFlowtable adds a device-less flowtable, which kernels without nf_flow_table reject just as
// they would the real one.
func probeFlowtable(ctx context.Context, nft knftables.Interface, name string, counter bool) bool {
	prio := knftables.FilterIngressPriority
	tx := nft.NewTransaction()
	tx.Add(&knftables.Table{})
	tx.Add(&knftables.Flowtable{
		Name:     name,
		Priority: &prio,
		Counter:  knftables.PtrTo(counter),
	})
	if err := nft.Run(ctx, tx); err != nil {
		logrus.WithError(err).WithField("counter", counter).Debug("Kernel rejected the flowtable probe.")
		return false
	}
	return true
}
