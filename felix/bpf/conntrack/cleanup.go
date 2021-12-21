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
	"net"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/timeshim"
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

type LivenessScanner struct {
	timeouts Timeouts
	dsr      bool
	time     timeshim.Interface

	// goTimeOfLastKTimeLookup is the go timestamp of the last time we looked up the kernel time.
	// We cache the kernel time because it's expensive to look up (vs looking up a go timestamp which uses vdso).
	goTimeOfLastKTimeLookup time.Time
	// cachedKTime is the most recent kernel time.
	cachedKTime int64
}

func NewLivenessScanner(timeouts Timeouts, dsr bool, opts ...LivenessScannerOpt) *LivenessScanner {
	ls := &LivenessScanner{
		timeouts: timeouts,
		dsr:      dsr,
		time:     timeshim.RealTime(),
	}
	for _, opt := range opts {
		opt(ls)
	}
	return ls
}

type LivenessScannerOpt func(ls *LivenessScanner)

func WithTimeShim(shim timeshim.Interface) LivenessScannerOpt {
	return func(ls *LivenessScanner) {
		ls.time = shim
	}
}

func (l *LivenessScanner) Check(ctKey Key, ctVal Value, get EntryGet) ScanVerdict {
	if l.cachedKTime == 0 || l.time.Since(l.goTimeOfLastKTimeLookup) > time.Second {
		l.cachedKTime = l.time.KTimeNanos()
		l.goTimeOfLastKTimeLookup = l.time.Now()
	}
	now := l.cachedKTime

	debug := log.GetLevel() >= log.DebugLevel

	switch ctVal.Type() {
	case TypeNATForward:
		// Look up the reverse entry, where we do the book-keeping.
		revEntry, err := get(ctVal.ReverseNATKey())
		if err != nil && bpf.IsNotExists(err) {
			// Forward entry exists but no reverse entry. We might have come across the reverse
			// entry first and removed it. It is useless on its own, so delete it now.
			//
			// N.B. BPF code always creates REV entry before FWD entry, therefore if the REV
			// entry does not exist now, we are not racing with the BPF code, we must have
			// removed the entry or there is some external inconsistency. In either case, the
			// FWD entry should be removed.
			log.Debug("Found a forward NAT conntrack entry with no reverse entry, removing...")
			return ScanVerdictDelete
		} else if err != nil {
			log.WithError(err).Warn("Failed to look up conntrack entry.")
			return ScanVerdictOK
		}
		if reason, expired := l.timeouts.EntryExpired(now, ctKey.Proto(), revEntry); expired {
			if debug {
				log.WithField("reason", reason).Debug("Deleting expired conntrack forward-NAT entry")
			}
			return ScanVerdictDelete
			// do not delete the reverse entry yet to avoid breaking the iterating
			// over the map.  We must not delete other than the current key. We remove
			// it once we come across it again.
		}
	case TypeNATReverse:
		if reason, expired := l.timeouts.EntryExpired(now, ctKey.Proto(), ctVal); expired {
			if debug {
				log.WithField("reason", reason).Debug("Deleting expired conntrack reverse-NAT entry")
			}
			return ScanVerdictDelete
		}
	case TypeNormal:
		if reason, expired := l.timeouts.EntryExpired(now, ctKey.Proto(), ctVal); expired {
			if debug {
				log.WithField("reason", reason).Debug("Deleting expired normal conntrack entry")
			}
			return ScanVerdictDelete
		}
	default:
		log.WithField("type", ctVal.Type()).Warn("Unknown conntrack entry type!")
	}

	return ScanVerdictOK
}

// EntryExpired checks whether a given conntrack table entry for a given
// protocol and time, is expired.
func (t *Timeouts) EntryExpired(nowNanos int64, proto uint8, entry Value) (reason string, expired bool) {
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
	case ProtoICMP:
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

// NATChecker returns true a given combination of frontend-backend exists
type NATChecker interface {
	ConntrackScanStart()
	ConntrackScanEnd()
	ConntrackFrontendHasBackend(ip net.IP, port uint16, backendIP net.IP, backendPort uint16, proto uint8) bool
}

// StaleNATScanner removes any entries to frontend that do not have the backend anymore.
type StaleNATScanner struct {
	natChecker NATChecker
}

// NewStaleNATScanner returns an EntryScanner that checks if entries have
// existing NAT entries using the provided NATChecker and if not, it deletes
// them.
func NewStaleNATScanner(frontendHasBackend NATChecker) *StaleNATScanner {
	return &StaleNATScanner{
		natChecker: frontendHasBackend,
	}
}

// Check checks the conntrack entry
func (sns *StaleNATScanner) Check(k Key, v Value, _ EntryGet) ScanVerdict {
	debug := log.GetLevel() >= log.DebugLevel

	switch v.Type() {
	case TypeNormal:
		// skip non-NAT entry

	case TypeNATReverse:
		proto := k.Proto()
		ipA := k.AddrA()
		ipB := k.AddrB()

		portA := k.PortA()
		portB := k.PortB()

		svcIP := v.OrigIP()
		svcPort := v.OrigPort()

		// We cannot tell which leg is EP and which is the client, we must
		// try both. If there is a record for one of them, it is still most
		// likely an active entry.
		if !sns.natChecker.ConntrackFrontendHasBackend(svcIP, svcPort, ipA, portA, proto) &&
			!sns.natChecker.ConntrackFrontendHasBackend(svcIP, svcPort, ipB, portB, proto) {
			if debug {
				log.WithField("key", k).Debugf("TypeNATReverse is stale")
			}
			return ScanVerdictDelete
		}
		if debug {
			log.WithField("key", k).Debugf("TypeNATReverse still active")
		}

	case TypeNATForward:
		proto := k.Proto()
		kA := k.AddrA()
		kAport := k.PortA()
		kB := k.AddrB()
		kBport := k.PortB()
		revKey := v.ReverseNATKey()
		revA := revKey.AddrA()
		revAport := revKey.PortA()
		revB := revKey.AddrB()
		revBport := revKey.PortB()

		var (
			svcIP, epIP     net.IP
			svcPort, epPort uint16
		)

		snatPort := v.NATSPort()

		// Because client IP/Port are both in fwd key and rev key, we can
		// can tell which one it is and thus determine exactly meaning of
		// the other values.
		if snatPort == 0 {
			if kA.Equal(revA) && kAport == revAport {
				epIP = revB
				epPort = revBport
				svcIP = kB
				svcPort = kBport
			} else if kB.Equal(revA) && kBport == revAport {
				epIP = revB
				epPort = revBport
				svcIP = kA
				svcPort = kAport
			} else if kA.Equal(revB) && kAport == revBport {
				epIP = revA
				epPort = revAport
				svcIP = kB
				svcPort = kBport
			} else if kB.Equal(revB) && kBport == revBport {
				epIP = revA
				epPort = revAport
				svcIP = kA
				svcPort = kAport
			} else {
				log.WithFields(log.Fields{"key": k, "value": v}).Error("Mismatch between key and rev key")
				return ScanVerdictOK // don't touch, will get deleted when expired
			}
		} else {
			// snatPort is the new client port. It does not match the client
			// port in the key. So we only check that the IPs match and the that
			// port is the snatPort.
			if kA.Equal(revA) && snatPort == revAport {
				epIP = revB
				epPort = revBport
				svcIP = kB
				svcPort = kBport
			} else if kB.Equal(revA) && snatPort == revAport {
				epIP = revB
				epPort = revBport
				svcIP = kA
				svcPort = kAport
			} else if kA.Equal(revB) && snatPort == revBport {
				epIP = revA
				epPort = revAport
				svcIP = kB
				svcPort = kBport
			} else if kB.Equal(revB) && snatPort == revBport {
				epIP = revA
				epPort = revAport
				svcIP = kA
				svcPort = kAport
			} else {
				log.WithFields(log.Fields{"key": k, "value": v}).Error("Mismatch between key and rev key")
				return ScanVerdictOK // don't touch, will get deleted when expired
			}
		}

		if !sns.natChecker.ConntrackFrontendHasBackend(svcIP, svcPort, epIP, epPort, proto) {
			if debug {
				log.WithField("key", k).Debugf("TypeNATForward is stale")
			}
			return ScanVerdictDelete
		}
		if debug {
			log.WithField("key", k).Debugf("TypeNATForward still active")
		}

	default:
		log.WithField("conntrack.Value.Type()", v.Type()).Warn("Unknown type")
	}

	return ScanVerdictOK
}

// IterationStart satisfies EntryScannerSynced
func (sns *StaleNATScanner) IterationStart() {
	sns.natChecker.ConntrackScanStart()
}

// IterationEnd satisfies EntryScannerSynced
func (sns *StaleNATScanner) IterationEnd() {
	sns.natChecker.ConntrackScanEnd()
}
