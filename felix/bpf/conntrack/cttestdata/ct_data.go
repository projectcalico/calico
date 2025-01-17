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

package cttestdata

import (
	"net"
	"time"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/timeshim/mocktime"
)

// Now is the current mock ktime, the mock conntrack entries are created in the
// near past relative to this time.
var Now = mocktime.StartKTime

var (
	ip1   = net.ParseIP("10.0.0.1")
	ip2   = net.ParseIP("10.0.0.2")
	ipSvc = net.ParseIP("10.96.0.1")

	tcpKey    = conntrack.NewKey(conntrack.ProtoTCP, ip1, 1234, ip2, 3456)
	tcpFwdKey = conntrack.NewKey(conntrack.ProtoTCP, ip1, 5555, ipSvc, 80)
	tcpRevKey = conntrack.NewKey(conntrack.ProtoTCP, ip1, 5555, ip2, 8080)

	udpKey    = conntrack.NewKey(conntrack.ProtoUDP, ip1, 1234, ip2, 3456)
	udpFwdKey = conntrack.NewKey(conntrack.ProtoUDP, ip1, 5555, ipSvc, 53)
	udpRevKey = conntrack.NewKey(conntrack.ProtoUDP, ip1, 5555, ip2, 5353)

	icmpKey    = conntrack.NewKey(conntrack.ProtoICMP, ip1, 1234, ip2, 3456)
	genericKey = conntrack.NewKey(253, ip1, 0, ip2, 0)

	genericAlmostTimedOut = makeValue(Now-(599*time.Second), conntrack.Leg{Approved: true}, conntrack.Leg{})
	genericTimedOut       = makeValue(Now-(601*time.Second), conntrack.Leg{Approved: true}, conntrack.Leg{})

	udpAlmostTimedOut = makeValue(Now-(59*time.Second), conntrack.Leg{Approved: true}, conntrack.Leg{})
	udpTimedOut       = makeValue(Now-(61*time.Second), conntrack.Leg{Approved: true}, conntrack.Leg{})

	icmpAlmostTimedOut = makeValue(Now-(4*time.Second), conntrack.Leg{Approved: true}, conntrack.Leg{})
	icmpTimedOut       = makeValue(Now-(6*time.Second), conntrack.Leg{Approved: true}, conntrack.Leg{})

	tcpHandshakeTimeout   = makeValue(Now-21*time.Second, conntrack.Leg{SynSeen: true}, conntrack.Leg{})
	tcpHandshakeTimeout2  = makeValue(Now-21*time.Second, conntrack.Leg{SynSeen: true}, conntrack.Leg{SynSeen: true, AckSeen: true})
	tcpEstablished        = makeValue(Now-1, conntrack.Leg{SynSeen: true, AckSeen: true}, conntrack.Leg{SynSeen: true, AckSeen: true})
	tcpEstablishedTimeout = makeValue(Now-(2*time.Hour), conntrack.Leg{SynSeen: true, AckSeen: true}, conntrack.Leg{SynSeen: true, AckSeen: true})
	tcpSingleFin          = makeValue(Now-(50*time.Minute), conntrack.Leg{SynSeen: true, AckSeen: true, FinSeen: true}, conntrack.Leg{SynSeen: true, AckSeen: true})
	tcpSingleFinTimeout   = makeValue(Now-(2*time.Hour), conntrack.Leg{SynSeen: true, AckSeen: true, FinSeen: true}, conntrack.Leg{SynSeen: true, AckSeen: true})
	tcpBothFin            = makeValue(Now-(29*time.Second), conntrack.Leg{SynSeen: true, AckSeen: true, FinSeen: true}, conntrack.Leg{SynSeen: true, AckSeen: true, FinSeen: true})
	tcpBothFinTimeout     = makeValue(Now-(31*time.Second), conntrack.Leg{SynSeen: true, AckSeen: true, FinSeen: true}, conntrack.Leg{SynSeen: true, AckSeen: true, FinSeen: true})
)

type CTCleanupTest struct {
	Description       string
	KVs               map[conntrack.Key]conntrack.Value
	ExpectedDeletions []conntrack.Key
}

var CTCleanupTests []CTCleanupTest

func addSingleKVTest(desc string, k conntrack.Key, v conntrack.Value, deletionExpected bool) {
	{
		// Add "normal" version of the test.
		tc := CTCleanupTest{
			Description: desc,
			KVs: map[conntrack.Key]conntrack.Value{
				k: v,
			},
		}
		if deletionExpected {
			tc.ExpectedDeletions = []conntrack.Key{k}
		}
		CTCleanupTests = append(CTCleanupTests, tc)
	}

	{
		// Add a version of the test with the legs reversed.
		var eReversed conntrack.Value
		copy(eReversed[:], v[:])
		copy(eReversed[24:32], v[32:40])
		copy(eReversed[32:40], v[24:32])

		tc := CTCleanupTest{
			Description: desc + " (legs reversed)",
			KVs: map[conntrack.Key]conntrack.Value{
				k: eReversed,
			},
		}
		if deletionExpected {
			tc.ExpectedDeletions = []conntrack.Key{k}
		}
		CTCleanupTests = append(CTCleanupTests, tc)
	}
}

func init() {
	CTCleanupTests = append(CTCleanupTests,
		CTCleanupTest{
			Description: "empty map",
		},

		CTCleanupTest{
			Description: "long-lived TCP NAT entries",
			KVs: map[conntrack.Key]conntrack.Value{
				// Note: last seen time on the forward entry should be ignored in
				// favour of the last-seen time on the reverse entry.
				tcpFwdKey: conntrack.NewValueNATForward(Now-3*time.Hour, 0, tcpRevKey),
				tcpRevKey: conntrack.NewValueNATReverse(Now-time.Second, 0,
					conntrack.Leg{SynSeen: true, AckSeen: true}, conntrack.Leg{SynSeen: true, AckSeen: true},
					nil, nil, 5555),
			},
		},

		CTCleanupTest{
			Description: "expired TCP NAT entries",
			KVs: map[conntrack.Key]conntrack.Value{
				// Note: last seen time on the forward entry should be ignored in
				// favour of the last-seen time on the reverse entry.
				tcpFwdKey: conntrack.NewValueNATForward(Now-3*time.Hour, 0, tcpRevKey),
				tcpRevKey: conntrack.NewValueNATReverse(Now-2*time.Hour, 0,
					conntrack.Leg{SynSeen: true, AckSeen: true}, conntrack.Leg{SynSeen: true, AckSeen: true},
					nil, nil, 5555),
			},
			ExpectedDeletions: []conntrack.Key{tcpFwdKey, tcpRevKey},
		},

		CTCleanupTest{
			Description: "forward NAT entry with no reverse entry",
			KVs: map[conntrack.Key]conntrack.Value{
				tcpFwdKey: conntrack.NewValueNATForward(Now-3*time.Hour, 0, tcpRevKey),
			},
			ExpectedDeletions: []conntrack.Key{tcpFwdKey},
		},
		CTCleanupTest{
			Description: "forward NAT entry without reverse out of grace period",
			KVs: map[conntrack.Key]conntrack.Value{
				tcpFwdKey: conntrack.NewValueNATForward(Now-11*time.Second, 0, tcpRevKey),
			},
			ExpectedDeletions: []conntrack.Key{tcpFwdKey},
		},

		CTCleanupTest{
			Description: "long-lived UDP NAT entries",
			KVs: map[conntrack.Key]conntrack.Value{
				// Note: last seen time on the forward entry should be ignored in
				// favour of the last-seen time on the reverse entry.
				udpFwdKey: conntrack.NewValueNATForward(Now-3*time.Hour, 0, udpRevKey),
				udpRevKey: conntrack.NewValueNATReverse(Now-time.Second, 0, conntrack.Leg{}, conntrack.Leg{}, nil, nil, 5555),
			},
		},
	)

	addSingleKVTest("TCP handshake timeout", tcpKey, tcpHandshakeTimeout, true)
	addSingleKVTest("TCP handshake timeout on response", tcpKey, tcpHandshakeTimeout2, true)
	addSingleKVTest("TCP established", tcpKey, tcpEstablished, false)
	addSingleKVTest("TCP established timed out", tcpKey, tcpEstablishedTimeout, true)
	addSingleKVTest("TCP single fin", tcpKey, tcpSingleFin, false)
	addSingleKVTest("TCP single fin timed out", tcpKey, tcpSingleFinTimeout, true)
	addSingleKVTest("TCP both fin", tcpKey, tcpBothFin, false)
	addSingleKVTest("TCP both fin timed out", tcpKey, tcpBothFinTimeout, true)

	addSingleKVTest("UDP almost timed out", udpKey, udpAlmostTimedOut, false)
	addSingleKVTest("UDP timed out", udpKey, udpTimedOut, true)

	addSingleKVTest("Generic almost timed out", genericKey, genericAlmostTimedOut, false)
	addSingleKVTest("Generic timed out", genericKey, genericTimedOut, true)

	addSingleKVTest("icmp almost timed out", icmpKey, icmpAlmostTimedOut, false)
	addSingleKVTest("icmp timed out", icmpKey, icmpTimedOut, true)
}

func makeValue(lastSeen time.Duration, legA conntrack.Leg, legB conntrack.Leg) conntrack.Value {
	return conntrack.NewValueNormal(lastSeen, 0, legA, legB)
}
