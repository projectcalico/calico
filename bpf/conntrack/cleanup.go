// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package conntrack

import (
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/bpf"
)

type Timeouts struct {
	CreationGracePeriod time.Duration

	TCPPreEstablished time.Duration
	TCPEstablished    time.Duration
	TCPFinsSeen       time.Duration
	TCPResetSeen      time.Duration

	UDPLastSeen time.Duration

	ICMPLastSeen time.Duration
}

func DefaultTimeouts() Timeouts {
	return Timeouts{
		CreationGracePeriod: 10 * time.Second,
		TCPPreEstablished:   20 * time.Second,
		TCPEstablished:      time.Hour,
		TCPFinsSeen:         30 * time.Second,
		TCPResetSeen:        40 * time.Second,
		UDPLastSeen:         60 * time.Second,
		ICMPLastSeen:        5 * time.Second,
	}
}

type LivenessScanner struct {
	timeouts Timeouts
	ctMap    bpf.Map
	dsr      bool
	NowNanos func() int64
}

func NewLivenessScanner(timeouts Timeouts, dsr bool, ctMap bpf.Map) *LivenessScanner {
	return &LivenessScanner{
		timeouts: timeouts,
		ctMap:    ctMap,
		dsr:      dsr,
		NowNanos: bpf.KTimeNanos,
	}
}

func (l *LivenessScanner) Scan() {
	err := l.ctMap.Iter(func(k, v []byte) {
		ctKey := keyFromBytes(k)
		ctVal := entryFromBytes(v)
		log.WithFields(log.Fields{
			"key":   ctKey,
			"entry": ctVal,
		}).Debug("Examining conntrack entry")

		now := l.NowNanos()

		switch ctVal.Type() {
		case TypeNATForward:
			// Look up the reverse entry, where we do the book-keeping.
			revEntryBytes, err := l.ctMap.Get(ctVal.ReverseNATKey().AsBytes())
			if err != nil && bpf.IsNotExists(err) {
				// Forward entry exists but no reverse entry (and the grace period has expired).
				log.Info("Found a forward NAT conntrack entry with no reverse entry, removing...")
				err := l.ctMap.Delete(k)
				log.WithError(err).Debug("Deletion result")
				if err != nil && !bpf.IsNotExists(err) {
					log.WithError(err).Warn("Failed to delete conntrack entry.")
				}
				return
			} else if err != nil {
				log.WithError(err).Warn("Failed to look up conntrack entry.")
				return
			}
			revEntry := entryFromBytes(revEntryBytes)
			if reason, expired := l.EntryExpired(now, ctKey.Proto(), revEntry); expired {
				log.WithField("reason", reason).Debug("Deleting expired conntrack forward-NAT entry")
				err := l.ctMap.Delete(k)
				log.WithError(err).Debug("Deletion result")
				if err != nil && !bpf.IsNotExists(err) {
					log.WithError(err).Warn("Failed to delete expired conntrack forward-NAT entry.")
				}
				err = l.ctMap.Delete(ctVal.ReverseNATKey().AsBytes())
				log.WithError(err).Debug("Deletion result")
				if err != nil && !bpf.IsNotExists(err) {
					log.WithError(err).Warn("Failed to delete expired conntrack reverse-NAT entry.")
				}
			}
		case TypeNATReverse:
			if reason, expired := l.EntryExpired(now, ctKey.Proto(), ctVal); expired {
				log.WithField("reason", reason).Debug("Deleting expired conntrack reverse-NAT entry")
				err := l.ctMap.Delete(k)
				log.WithError(err).Debug("Deletion result")
				if err != nil && !bpf.IsNotExists(err) {
					log.WithError(err).Warn("Failed to delete expired conntrack forward-NAT entry.")
				}
				// TODO Handle forward entry.
			}
		case TypeNormal:
			if reason, expired := l.EntryExpired(now, ctKey.Proto(), ctVal); expired {
				log.WithField("reason", reason).Debug("Deleting expired normal conntrack entry")
				err := l.ctMap.Delete(k)
				log.WithError(err).Debug("Deletion result")
				if err != nil && !bpf.IsNotExists(err) {
					log.WithError(err).Warn("Failed to delete expired conntrack forward-NAT entry.")
				}
			}
		default:
			log.WithField("type", ctVal.Type()).Warn("Unknown conntrack entry type!")
		}
	})
	if err != nil {
		log.WithError(err).Warn("Failed to iterate over conntrack map")
	}
}

func (l *LivenessScanner) EntryExpired(nowNanos int64, proto uint8, entry Value) (reason string, expired bool) {
	sinceCreation := time.Duration(nowNanos - entry.Created())
	if sinceCreation < l.timeouts.CreationGracePeriod {
		log.Debug("Conntrack entry in creation grace period. Ignoring.")
		return
	}
	age := time.Duration(nowNanos - entry.LastSeen())
	switch proto {
	case ProtoTCP:
		dsr := entry.IsForwardDSR()
		data := entry.Data()
		rstSeen := data.RSTSeen()
		if rstSeen && age > l.timeouts.TCPResetSeen {
			return "RST seen", true
		}
		finsSeen := (dsr && data.FINsSeenDSR()) || data.FINsSeen()
		if finsSeen && age > l.timeouts.TCPFinsSeen {
			// Both legs have been finished, tear down.
			return "FINs seen", true
		}
		if data.Established() || dsr {
			if age > l.timeouts.TCPEstablished {
				return "no traffic on established flow for too long", true
			}
		} else {
			if age > l.timeouts.TCPPreEstablished {
				return "no traffic on pre-established flow for too long", true
			}
		}
		return "", false
	case ProtoICMP:
		if age > l.timeouts.ICMPLastSeen {
			return "no traffic on ICMP flow for too long", true
		}
	default:
		// FIXME separate timeouts for non-UDP IP traffic?
		if age > l.timeouts.UDPLastSeen {
			return "no traffic on UDP flow for too long", true
		}
	}
	return "", false
}
