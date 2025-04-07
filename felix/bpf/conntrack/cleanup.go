// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.
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
	"golang.org/x/sys/unix"

	v3 "github.com/projectcalico/calico/felix/bpf/conntrack/v3"
	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/timeshim"
)

type LivenessScanner struct {
	timeouts Timeouts
	dsr      bool
	time     timeshim.Interface

	// goTimeOfLastKTimeLookup is the go timestamp of the last time we looked up the kernel time.
	// We cache the kernel time because it's expensive to look up (vs looking up a go timestamp which uses vdso).
	goTimeOfLastKTimeLookup time.Time
	// cachedKTime is the most recent kernel time.
	cachedKTime int64

	scanCtx CleanupContext
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

func (l *LivenessScanner) Check(ctKey KeyInterface, ctVal ValueInterface, get EntryGet) ScanVerdict {
	if l.cachedKTime == 0 || l.time.Since(l.goTimeOfLastKTimeLookup) > time.Second {
		l.cachedKTime = l.time.KTimeNanos()
		l.goTimeOfLastKTimeLookup = l.time.Now()
	}
	now := l.cachedKTime

	debug := log.GetLevel() >= log.DebugLevel

	switch ctVal.Type() {
	case TypeNATForward:
		l.scanCtx.NumKVsSeenNATForward++
		// Look up the reverse entry, where we do the bookkeeping.
		revEntry, err := get(ctVal.ReverseNATKey())
		if err != nil && maps.IsNotExists(err) {
			// Forward entry exists but no reverse entry. We might have come across the reverse
			// entry first and removed it. It is useless on its own, so delete it now.
			if debug {
				log.WithField("k", ctKey).Debug("Deleting forward NAT conntrack entry with no reverse entry.")
			}
			l.scanCtx.NumKVsDeletedNATForward++
			return ScanVerdictDelete
		} else if err != nil {
			log.WithFields(log.Fields{
				"fwdKey": ctKey,
				"revKey": ctVal.ReverseNATKey(),
			}).WithError(err).Warn("Failed to look up reverse conntrack entry.")
			return ScanVerdictOK
		}
		if reason, expired := l.timeouts.EntryExpired(now, ctKey.Proto(), revEntry); expired {
			if debug {
				log.WithFields(log.Fields{
					"reason": reason,
					"key":    ctKey,
				}).Debug("Deleting expired conntrack forward-NAT entry")
			}
			l.scanCtx.NumKVsDeletedNATForward++
			return ScanVerdictDelete
			// do not delete the reverse entry yet to avoid breaking the iterating
			// over the map.  We must not delete other than the current key. We remove
			// it once we come across it again.
		}
	case TypeNATReverse:
		l.scanCtx.NumKVsSeenNATReverse++
		if reason, expired := l.timeouts.EntryExpired(now, ctKey.Proto(), ctVal); expired {
			if debug {
				log.WithFields(log.Fields{
					"reason": reason,
					"key":    ctKey,
				}).Debug("Deleting expired conntrack reverse-NAT entry")
			}
			l.scanCtx.NumKVsDeletedNATReverse++
			return ScanVerdictDelete
		}
	case TypeNormal:
		l.scanCtx.NumKVsSeenNormal++
		if reason, expired := l.timeouts.EntryExpired(now, ctKey.Proto(), ctVal); expired {
			if debug {
				log.WithFields(log.Fields{
					"reason": reason,
					"key":    ctKey,
				}).Debug("Deleting expired normal conntrack entry")
			}
			l.scanCtx.NumKVsDeletedNormal++
			return ScanVerdictDelete
		}
	default:
		log.WithFields(log.Fields{
			"type": ctVal.Type(),
			"key":  ctKey,
		}).Warn("Unknown conntrack entry type!")
	}

	return ScanVerdictOK
}

// IterationStart satisfies EntryScannerSynced
func (l *LivenessScanner) IterationStart() {
	l.scanCtx.NumKVsSeenNormal = 0
	l.scanCtx.NumKVsSeenNATForward = 0
	l.scanCtx.NumKVsSeenNATReverse = 0

	l.scanCtx.NumKVsDeletedNormal = 0
	l.scanCtx.NumKVsDeletedNATForward = 0
	l.scanCtx.NumKVsDeletedNATReverse = 0
}

// IterationEnd satisfies EntryScannerSynced
func (l *LivenessScanner) IterationEnd() {
	gaugeVecConntrackEntries.WithLabelValues("normal").Set(float64(l.scanCtx.NumKVsSeenNormal))
	gaugeVecConntrackEntries.WithLabelValues("nat_forward").Set(float64(l.scanCtx.NumKVsSeenNATForward))
	gaugeVecConntrackEntries.WithLabelValues("nat_reverse").Set(float64(l.scanCtx.NumKVsSeenNATReverse))

	counterVecConntrackEntriesDeleted.WithLabelValues("normal").Add(float64(l.scanCtx.NumKVsDeletedNormal))
	counterVecConntrackEntriesDeleted.WithLabelValues("nat_forward").Add(float64(l.scanCtx.NumKVsDeletedNATForward))
	counterVecConntrackEntriesDeleted.WithLabelValues("nat_reverse").Add(float64(l.scanCtx.NumKVsDeletedNATReverse))
}

// NATChecker returns true a given combination of frontend-backend exists
type NATChecker interface {
	ConntrackScanStart()
	ConntrackScanEnd()
	ConntrackFrontendHasBackend(ip net.IP, port uint16, backendIP net.IP, backendPort uint16, proto uint8) bool
	ConntrackDestIsService(ip net.IP, port uint16, proto uint8) bool
}

// StaleNATScanner removes any entries to frontend that do not have the backend anymore.
type StaleNATScanner struct {
	natChecker NATChecker
	scanCtx    CleanupContext
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
func (sns *StaleNATScanner) Check(k KeyInterface, v ValueInterface, get EntryGet) ScanVerdict {
	debug := log.GetLevel() >= log.DebugLevel

again:

	switch v.Type() {
	case TypeNormal:
		proto := k.Proto()
		if proto != ProtoUDP {
			// skip non-NAT entry
			break
		}

		// Check if we have an entry to a service IP:port without it being
		// NATed. Remove such entry as it was created when the service wasn't
		// programmed yet and there was a NAT miss.
		//
		// When CTLB is used, we should not see service ip:port on the wire at
		// all.

		var (
			ip   net.IP
			port uint16
		)

		if v.Flags()&v3.FlagSrcDstBA != 0 {
			ip = k.AddrA()
			port = k.PortA()
		} else {
			ip = k.AddrB()
			port = k.PortB()
		}

		if sns.natChecker.ConntrackDestIsService(ip, port, proto) {
			log.WithField("key", k).Debugf("TypeNormal to UDP service IP is stale")
			return ScanVerdictDelete
		}

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
			sns.scanCtx.NumKVsDeletedNATReverse++
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
				rv, err := get(revKey)
				if err != nil {
					if err == unix.ENOENT {
						// There is no match for the reverse key, delete it, its useless - we
						// can get here due to host networked program accessing service
						// without ctlb when the backed is accessible via tunnel.
						if debug {
							log.WithFields(log.Fields{"key": k, "value": v}).
								Debug("Mismatch between key and rev key - " +
									"deleting entry because reverse key does not exist.")
						}
						sns.scanCtx.NumKVsDeletedNATForward++
						return ScanVerdictDelete
					} else {
						if debug {
							// In the worst case, the entry will timeout
							log.WithFields(log.Fields{"key": k, "value": v}).WithError(err).
								Debug("Mismatch between key and rev key - " +
									"keeping entry, failed to retrieve reverse entry. Will try again.")
						}
						return ScanVerdictOK
					}
				}
				k = revKey
				v = rv
				goto reverse // handle it based on the reverse entry
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
				rv, err := get(revKey)
				if err != nil {
					if err == unix.ENOENT {
						// There is no match for the reverse key, delete it, its useless - we
						// can get here due to host networked program accessing service
						// without ctlb when the backed is accessible via tunnel.
						if debug {
							log.WithFields(log.Fields{"key": k, "value": v}).
								Debug("Mismatch between key and rev key - " +
									"deleting entry because reverse key does not exist.")
						}
						sns.scanCtx.NumKVsDeletedNATForward++
						return ScanVerdictDelete
					} else {
						if debug {
							// In the worst case, the entry will timeout
							log.WithFields(log.Fields{"key": k, "value": v}).WithError(err).
								Debug("Mismatch between key and rev key - " +
									"keeping entry, failed to retrieve reverse entry. Will try again.")
						}
						return ScanVerdictOK
					}
				}
				k = revKey
				v = rv
				goto reverse // handle it based on the reverse entry
			}
		}

		if !sns.natChecker.ConntrackFrontendHasBackend(svcIP, svcPort, epIP, epPort, proto) {
			if debug {
				log.WithField("key", k).Debugf("TypeNATForward is stale")
			}
			sns.scanCtx.NumKVsDeletedNATForward++
			return ScanVerdictDelete
		}
		if debug {
			log.WithField("key", k).Debugf("TypeNATForward still active")
		}

	default:
		log.WithField("conntrack.Value.Type()", v.Type()).Warn("Unknown type")
	}

	return ScanVerdictOK

reverse:
	if v.Type() == TypeNATReverse {
		goto again
	}

	if debug {
		log.WithFields(log.Fields{"key": k, "value": v}).
			Debug("Mismatch between key and rev key - " +
				"deleting entry because reverse key does not point to a reverse entry.")
	}

	sns.scanCtx.NumKVsDeletedNATForward++
	return ScanVerdictDelete
}

// IterationStart satisfies EntryScannerSynced
func (sns *StaleNATScanner) IterationStart() {
	sns.natChecker.ConntrackScanStart()

	// Track 'NumKVsDelete*' metrics only; 'NumKVsSeen*' metrics are tracked by LivenessScanner.
	sns.scanCtx.NumKVsDeletedNATForward = 0
	sns.scanCtx.NumKVsDeletedNATReverse = 0
}

// IterationEnd satisfies EntryScannerSynced
func (sns *StaleNATScanner) IterationEnd() {
	sns.natChecker.ConntrackScanEnd()

	// Track 'NumKVsDelete*' metrics only; 'NumKVsSeen*' metrics are tracked by LivenessScanner.
	counterVecConntrackEntriesDeleted.WithLabelValues("nat_forward").Add(float64(sns.scanCtx.NumKVsDeletedNATForward))
	counterVecConntrackEntriesDeleted.WithLabelValues("nat_reverse").Add(float64(sns.scanCtx.NumKVsDeletedNATReverse))
}
