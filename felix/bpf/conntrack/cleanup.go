// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/timeshim"
)

var (
	conntrackGaugeExpired = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_bpf_conntrack_expired",
		Help: "Number of entries cleaned during a conntrack table sweep due to expiration",
	})
	conntrackCountersExpired = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "felix_bpf_conntrack_expired_total",
		Help: "Total number of entries cleaned during conntrack table sweep due to expiration - by reason",
	}, []string{"reason"})
	conntrackGaugeStaleNAT = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_bpf_conntrack_stale_nat",
		Help: "Number of entries cleaned during a conntrack table sweep due to stale NAT",
	})
	conntrackCounterStaleNAT = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_bpf_conntrack_stale_nat_total",
		Help: "Total number of entries cleaned during conntrack table sweeps due to stale NAT",
	})
)

func init() {
	prometheus.MustRegister(conntrackGaugeExpired)
	prometheus.MustRegister(conntrackCountersExpired)
	prometheus.MustRegister(conntrackGaugeStaleNAT)
	prometheus.MustRegister(conntrackCounterStaleNAT)
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
	cleaned     int

	reasonCounters map[string]prometheus.Counter
}

func NewLivenessScanner(timeouts Timeouts, dsr bool, opts ...LivenessScannerOpt) *LivenessScanner {
	ls := &LivenessScanner{
		timeouts:       timeouts,
		dsr:            dsr,
		time:           timeshim.RealTime(),
		reasonCounters: make(map[string]prometheus.Counter),
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

func (l *LivenessScanner) reasonCounterInc(reason string) {
	c, ok := l.reasonCounters[reason]
	if !ok {
		var err error
		c, err = conntrackCountersExpired.GetMetricWithLabelValues(reason)
		if err != nil {
			log.WithError(err).Panicf("Failed to get conntrackCountersExpired counter for reason%q", reason)
		}
		l.reasonCounters[reason] = c
	}
	c.Inc()
	l.cleaned++
}

func (l *LivenessScanner) Check(ctKey KeyInterface, ctVal ValueInterface, get EntryGet) ScanVerdict {
	if l.cachedKTime == 0 || l.time.Since(l.goTimeOfLastKTimeLookup) > time.Second {
		l.cachedKTime = l.time.KTimeNanos()
		l.goTimeOfLastKTimeLookup = l.time.Now()
	}
	now := l.cachedKTime

	if now-ctVal.Created() < int64(l.timeouts.CreationGracePeriod) {
		// Very new entry; make sure we don't delete it while dataplane is still
		// setting it up.
		return ScanVerdictOK
	}

	debug := log.GetLevel() >= log.DebugLevel

	switch ctVal.Type() {
	case TypeNATForward:
		// Look up the reverse entry, where we do the bookkeeping.
		revEntry, err := get(ctVal.ReverseNATKey())
		if err != nil && maps.IsNotExists(err) {
			// Forward entry exists but no reverse entry. We might have come across the reverse
			// entry first and removed it. It is useless on its own, so delete it now.
			l.reasonCounterInc("no reverse for forward")
			if debug {
				log.WithField("k", ctKey).Debug("Deleting forward NAT conntrack entry with no reverse entry.")
			}
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
			l.reasonCounterInc(reason)
			return ScanVerdictDelete
			// do not delete the reverse entry yet to avoid breaking the iterating
			// over the map.  We must not delete other than the current key. We remove
			// it once we come across it again.
		}
	case TypeNATReverse:
		if reason, expired := l.timeouts.EntryExpired(now, ctKey.Proto(), ctVal); expired {
			if debug {
				log.WithFields(log.Fields{
					"reason": reason,
					"key":    ctKey,
				}).Debug("Deleting expired conntrack reverse-NAT entry")
			}
			l.reasonCounterInc(reason)
			return ScanVerdictDelete
		}
	case TypeNormal:
		if reason, expired := l.timeouts.EntryExpired(now, ctKey.Proto(), ctVal); expired {
			if debug {
				log.WithFields(log.Fields{
					"reason": reason,
					"key":    ctKey,
				}).Debug("Deleting expired normal conntrack entry")
			}
			l.reasonCounterInc(reason)
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
}

// IterationEnd satisfies EntryScannerSynced
func (l *LivenessScanner) IterationEnd() {
	conntrackGaugeExpired.Set(float64(l.cleaned))
	l.cleaned = 0
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
	cleaned    int
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
			sns.cleaned++
			conntrackCounterStaleNAT.Inc()
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
			sns.cleaned++
			conntrackCounterStaleNAT.Inc()
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

	return ScanVerdictDelete
}

// IterationStart satisfies EntryScannerSynced
func (sns *StaleNATScanner) IterationStart() {
	sns.natChecker.ConntrackScanStart()
}

// IterationEnd satisfies EntryScannerSynced
func (sns *StaleNATScanner) IterationEnd() {
	sns.natChecker.ConntrackScanEnd()
	conntrackGaugeStaleNAT.Set(float64(sns.cleaned))
	sns.cleaned = 0
}
