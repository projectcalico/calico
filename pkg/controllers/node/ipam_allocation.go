// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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
package node

import (
	"fmt"
	"time"

	"github.com/projectcalico/libcalico-go/lib/ipam"
	log "github.com/sirupsen/logrus"
)

// allocation is an internal structure used by the IPAM garbage collector to track IPAM
// allocations and their status with respect to garbage collection.
type allocation struct {
	ip     string
	handle string
	attrs  map[string]string

	// The Kubernetes node name hosting this allocation.
	knode string

	// leakedAt is the time we first identified this allocation
	// to be a leak candidate.
	leakedAt *time.Time

	// confirmedLeak is set to true when we are confident this allocation
	// is a leaked IP.
	confirmedLeak bool
}

func (a *allocation) fields() log.Fields {
	f := log.Fields{
		"ip":     a.ip,
		"handle": a.handle,
		"node":   a.attrs[ipam.AttributeNode],
	}

	if a.isPodIP() {
		ns := a.attrs[ipam.AttributeNamespace]
		pod := a.attrs[ipam.AttributePod]
		f["pod"] = fmt.Sprintf("%s/%s", ns, pod)
	}

	return f
}

func (a *allocation) node() string {
	if node, ok := a.attrs[ipam.AttributeNode]; ok {
		return node
	}
	return ""
}

func (a *allocation) markLeak(leakGracePeriod time.Duration) {
	if a.leakedAt == nil {
		t := time.Now()
		a.leakedAt = &t
		log.WithFields(a.fields()).Infof("Candidate IP leak")
	}

	if time.Since(*a.leakedAt) > leakGracePeriod && !a.isConfirmedLeak() {
		if leakGracePeriod > 0 {
			// If the duration is 0, that means the user has turned off IPAM GC.
			// We don't want to mark as a confirmed leak. We still allow marking as a candidate
			// leak for informational purposes.
			a.markConfirmedLeak()
		}
	}
}

func (a *allocation) markConfirmedLeak() {
	if a.confirmedLeak {
		// Already confirmed - nothing to do.
		return
	}
	if a.leakedAt == nil {
		log.WithFields(a.fields()).Warnf("Confirmed IP leak")
	} else {
		log.WithFields(a.fields()).Warnf("Confirmed IP leak after %s", time.Since(*a.leakedAt))
	}
	a.confirmedLeak = true
}

func (a *allocation) markValid() {
	if a.leakedAt != nil {
		log.WithFields(a.fields()).Infof("Confirmed valid IP after %s", time.Since(*a.leakedAt))
	}
	a.confirmedLeak = false
	a.leakedAt = nil
}

func (a *allocation) isConfirmedLeak() bool {
	return a.confirmedLeak
}

func (a *allocation) isPodIP() bool {
	ns := a.attrs[ipam.AttributeNamespace]
	pod := a.attrs[ipam.AttributePod]

	return ns != "" && pod != ""
}

func (a *allocation) isTunnelAddress() bool {
	ipip := a.attrs[ipam.AttributeType] == ipam.AttributeTypeIPIP
	vxlan := a.attrs[ipam.AttributeType] == ipam.AttributeTypeVXLAN
	wg := a.attrs[ipam.AttributeType] == ipam.AttributeTypeWireguard
	return ipip || vxlan || wg
}

func (a *allocation) isWindowsReserved() bool {
	return a.handle == ipam.WindowsReservedHandle
}
