// Copyright (c) 2024 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package conntrack

import (
	"time"

	log "github.com/sirupsen/logrus"
)

type Timeouts struct {
	CreationGracePeriod time.Duration

	TCPPreEstablished time.Duration
	TCPEstablished    time.Duration
	TCPFinsSeen       time.Duration
	TCPResetSeen      time.Duration

	UDPLastSeen time.Duration

	// GenericIPLastSeen is the timeout for IP protocols that we don't know.
	GenericIPLastSeen time.Duration

	ICMPLastSeen time.Duration
}

// EntryExpired checks whether a given conntrack table entry for a given
// protocol and time, is expired.
//
// WARNING: this implementation is duplicated in the conntrack_cleanup.c BPF
// program.
func (t *Timeouts) EntryExpired(nowNanos int64, proto uint8, entry ValueInterface) (reason string, expired bool) {
	sinceCreation := time.Duration(nowNanos - entry.Created())
	if sinceCreation < t.CreationGracePeriod {
		log.Debug("Conntrack entry in creation grace period. Ignoring.")
		return
	}
	age := time.Duration(nowNanos - entry.LastSeen())
	switch proto {
	case ProtoTCP:
		dsr := entry.IsForwardDSR()
		data := entry.Data()
		rstSeen := data.RSTSeen()
		if rstSeen && age > t.TCPResetSeen {
			return "RST seen", true
		}
		finsSeen := (dsr && data.FINsSeenDSR()) || data.FINsSeen()
		if finsSeen && age > t.TCPFinsSeen {
			// Both legs have been finished, tear down.
			return "FINs seen", true
		}
		if data.Established() || dsr {
			if age > t.TCPEstablished {
				return "no traffic on established flow for too long", true
			}
		} else {
			if age > t.TCPPreEstablished {
				return "no traffic on pre-established flow for too long", true
			}
		}
		return "", false
	case ProtoICMP, ProtoICMP6:
		if age > t.ICMPLastSeen {
			return "no traffic on ICMP flow for too long", true
		}
	case ProtoUDP:
		if age > t.UDPLastSeen {
			return "no traffic on UDP flow for too long", true
		}
	default:
		if age > t.GenericIPLastSeen {
			return "no traffic on generic IP flow for too long", true
		}
	}
	return "", false
}

func DefaultTimeouts() Timeouts {
	return Timeouts{
		CreationGracePeriod: 10 * time.Second,
		TCPPreEstablished:   20 * time.Second,
		TCPEstablished:      time.Hour,
		TCPFinsSeen:         30 * time.Second,
		TCPResetSeen:        40 * time.Second,
		UDPLastSeen:         60 * time.Second,
		GenericIPLastSeen:   600 * time.Second,
		ICMPLastSeen:        5 * time.Second,
	}
}
