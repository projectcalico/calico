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

package ippool

import (
	"context"
	"fmt"
	"math/big"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam/accounting"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

const (
	nearlyFullPercent = 80

	// Pools this small fill up after a handful of pods, so the condition would only be noise.
	minAddressesForNearlyFull = 32

	// utilizationDelay collapses block and reservation churn into at most one reconcile per interval.
	utilizationDelay = 5 * time.Second
)

// reconcileNearlyFull sets AddressSpaceNearlyFull on pools at or over the threshold and removes it from the rest.
func (c *IPPoolController) reconcileNearlyFull(ctx context.Context, pools []*v3.IPPool) error {
	var errs []error
	for _, p := range pools {
		counts, ok := c.tracker.Summarize(p.Name)
		if !ok {
			continue
		}

		var err error
		if cond := nearlyFullCondition(counts); cond != nil {
			err = updateCondition(ctx, c.cli, p, *cond)
		} else {
			err = removeCondition(ctx, c.cli, p, v3.IPPoolConditionAddressSpaceNearlyFull)
		}
		if err != nil {
			logrus.WithError(err).WithField("pool", p.Name).Error("Failed to update AddressSpaceNearlyFull on IPPool")
			errs = append(errs, err)
		}
	}
	return utilerrors.NewAggregate(errs)
}

// nearlyFullCondition returns the condition a pool with these counts should carry, or nil if it is under the threshold.
func nearlyFullCondition(counts *accounting.Counts) *metav1.Condition {
	total := counts.Total
	if total.Cmp(big.NewInt(minAddressesForNearlyFull)) <= 0 {
		return nil
	}

	// Compare used*100 against total*threshold so IPv6 totals never go through a float.
	used := new(big.Int).Sub(total, counts.Free())
	usedScaled := new(big.Int).Mul(used, big.NewInt(100))
	if usedScaled.Cmp(new(big.Int).Mul(total, big.NewInt(nearlyFullPercent))) < 0 {
		return nil
	}

	// The message carries only the percentage, so it changes, and costs a status write, at most once per point.
	percent := new(big.Int).Quo(usedScaled, total)
	return &metav1.Condition{
		Type:    v3.IPPoolConditionAddressSpaceNearlyFull,
		Status:  metav1.ConditionTrue,
		Reason:  v3.IPPoolReasonThresholdExceeded,
		Message: fmt.Sprintf("%s%% of addresses are in use or reserved.", percent),
	}
}

func (c *IPPoolController) blockHandlers() cache.ResourceEventHandlerFuncs {
	add := func(obj any) {
		block, ok := toAllocationBlock(obj)
		if !ok {
			return
		}
		c.tracker.AddBlocks(block)
		c.queue.AddAfter(reconcileKey, utilizationDelay)
	}
	return cache.ResourceEventHandlerFuncs{
		AddFunc:    add,
		UpdateFunc: func(_, newObj any) { add(newObj) },
		DeleteFunc: func(obj any) {
			block, ok := unwrapTombstone(obj).(*v3.IPAMBlock)
			if !ok {
				return
			}
			_, cidr, err := cnet.ParseCIDR(block.Spec.CIDR)
			if err != nil {
				logrus.WithError(err).WithField("cidr", block.Spec.CIDR).Error("Failed to parse CIDR from deleted IPAMBlock")
				return
			}
			c.tracker.RemoveBlock(*cidr)

			// Block deletions can unblock finalization of a deleting pool, so reconcile straight away.
			c.queue.Add(reconcileKey)
		},
	}
}

func (c *IPPoolController) reservationHandlers() cache.ResourceEventHandlerFuncs {
	add := func(obj any) {
		reservation, ok := obj.(*v3.IPReservation)
		if !ok {
			return
		}
		c.tracker.AddReservations(reservation)
		c.queue.AddAfter(reconcileKey, utilizationDelay)
	}
	return cache.ResourceEventHandlerFuncs{
		AddFunc:    add,
		UpdateFunc: func(_, newObj any) { add(newObj) },
		DeleteFunc: func(obj any) {
			reservation, ok := unwrapTombstone(obj).(*v3.IPReservation)
			if !ok {
				return
			}
			c.tracker.RemoveReservation(reservation.Name)
			c.queue.AddAfter(reconcileKey, utilizationDelay)
		},
	}
}

func toAllocationBlock(obj any) (*model.AllocationBlock, bool) {
	block, ok := obj.(*v3.IPAMBlock)
	if !ok {
		logrus.WithField("type", fmt.Sprintf("%T", obj)).Error("Unexpected object type in IPAMBlock cache")
		return nil, false
	}
	kvp, err := resources.IPAMBlockV3toV1(&model.KVPair{Value: block})
	if err != nil {
		logrus.WithError(err).WithField("block", block.Name).Error("Failed to convert IPAMBlock")
		return nil, false
	}
	allocationBlock, ok := kvp.Value.(*model.AllocationBlock)
	if !ok {
		logrus.WithField("type", fmt.Sprintf("%T", kvp.Value)).Error("Unexpected IPAMBlock conversion result")
		return nil, false
	}
	return allocationBlock, true
}

func unwrapTombstone(obj any) any {
	if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		return tombstone.Obj
	}
	return obj
}
