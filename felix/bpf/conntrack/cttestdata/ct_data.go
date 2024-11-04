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
	ip1        = net.ParseIP("10.0.0.1")
	ip2        = net.ParseIP("10.0.0.2")
	tcpKey     = conntrack.NewKey(conntrack.ProtoTCP, ip1, 1234, ip2, 3456)
	udpKey     = conntrack.NewKey(conntrack.ProtoUDP, ip1, 1234, ip2, 3456)
	icmpKey    = conntrack.NewKey(conntrack.ProtoICMP, ip1, 1234, ip2, 3456)
	genericKey = conntrack.NewKey(253, ip1, 0, ip2, 0)

	genericJustCreated    = makeValue(Now-1, Now-1, conntrack.Leg{}, conntrack.Leg{})
	genericAlmostTimedOut = makeValue(Now-(20*time.Minute), Now-(599*time.Second), conntrack.Leg{Approved: true}, conntrack.Leg{})
	genericTimedOut       = makeValue(Now-(20*time.Minute), Now-(601*time.Second), conntrack.Leg{Approved: true}, conntrack.Leg{})

	udpJustCreated    = makeValue(Now-1, Now-1, conntrack.Leg{}, conntrack.Leg{})
	udpAlmostTimedOut = makeValue(Now-(2*time.Minute), Now-(59*time.Second), conntrack.Leg{Approved: true}, conntrack.Leg{})
	udpTimedOut       = makeValue(Now-(2*time.Minute), Now-(61*time.Second), conntrack.Leg{Approved: true}, conntrack.Leg{})

	icmpJustCreated    = makeValue(Now-1, Now-1, conntrack.Leg{}, conntrack.Leg{})
	icmpAlmostTimedOut = makeValue(Now-(2*time.Minute), Now-(4*time.Second), conntrack.Leg{Approved: true}, conntrack.Leg{})
	icmpTimedOut       = makeValue(Now-(2*time.Minute), Now-(6*time.Second), conntrack.Leg{Approved: true}, conntrack.Leg{})

	tcpJustCreated        = makeValue(Now-1, Now-1, conntrack.Leg{SynSeen: true}, conntrack.Leg{})
	tcpHandshakeTimeout   = makeValue(Now-22*time.Second, Now-21*time.Second, conntrack.Leg{SynSeen: true}, conntrack.Leg{})
	tcpHandshakeTimeout2  = makeValue(Now-22*time.Second, Now-21*time.Second, conntrack.Leg{SynSeen: true}, conntrack.Leg{SynSeen: true, AckSeen: true})
	tcpEstablished        = makeValue(Now-(10*time.Second), Now-1, conntrack.Leg{SynSeen: true, AckSeen: true}, conntrack.Leg{SynSeen: true, AckSeen: true})
	tcpEstablishedTimeout = makeValue(Now-(3*time.Hour), Now-(2*time.Hour), conntrack.Leg{SynSeen: true, AckSeen: true}, conntrack.Leg{SynSeen: true, AckSeen: true})
	tcpSingleFin          = makeValue(Now-(3*time.Hour), Now-(50*time.Minute), conntrack.Leg{SynSeen: true, AckSeen: true, FinSeen: true}, conntrack.Leg{SynSeen: true, AckSeen: true})
	tcpSingleFinTimeout   = makeValue(Now-(3*time.Hour), Now-(2*time.Hour), conntrack.Leg{SynSeen: true, AckSeen: true, FinSeen: true}, conntrack.Leg{SynSeen: true, AckSeen: true})
	tcpBothFin            = makeValue(Now-(3*time.Hour), Now-(29*time.Second), conntrack.Leg{SynSeen: true, AckSeen: true, FinSeen: true}, conntrack.Leg{SynSeen: true, AckSeen: true, FinSeen: true})
	tcpBothFinTimeout     = makeValue(Now-(3*time.Hour), Now-(31*time.Second), conntrack.Leg{SynSeen: true, AckSeen: true, FinSeen: true}, conntrack.Leg{SynSeen: true, AckSeen: true, FinSeen: true})
)

type CTCleanupTest struct {
	Description       string
	KVs               map[conntrack.Key]conntrack.Value
	ExpectedDeletions []conntrack.Key
}

var CTCleanupTests []CTCleanupTest

func defineSingleKVTest(desc string, k conntrack.Key, v conntrack.Value, deletionExpected bool) {
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
	defineSingleKVTest("TCP just created", tcpKey, tcpJustCreated, false)
	defineSingleKVTest("TCP handshake timeout", tcpKey, tcpHandshakeTimeout, true)
	defineSingleKVTest("TCP handshake timeout on response", tcpKey, tcpHandshakeTimeout2, true)
	defineSingleKVTest("TCP established", tcpKey, tcpEstablished, false)
	defineSingleKVTest("TCP established timed out", tcpKey, tcpEstablishedTimeout, true)
	defineSingleKVTest("TCP single fin", tcpKey, tcpSingleFin, false)
	defineSingleKVTest("TCP single fin timed out", tcpKey, tcpSingleFinTimeout, true)
	defineSingleKVTest("TCP both fin", tcpKey, tcpBothFin, false)
	defineSingleKVTest("TCP both fin timed out", tcpKey, tcpBothFinTimeout, true)

	defineSingleKVTest("UDP just created", udpKey, udpJustCreated, false)
	defineSingleKVTest("UDP almost timed out", udpKey, udpAlmostTimedOut, false)
	defineSingleKVTest("UDP timed out", udpKey, udpTimedOut, true)

	defineSingleKVTest("Generic just created", genericKey, genericJustCreated, false)
	defineSingleKVTest("Generic almost timed out", genericKey, genericAlmostTimedOut, false)
	defineSingleKVTest("Generic timed out", genericKey, genericTimedOut, true)

	defineSingleKVTest("icmp just created", icmpKey, icmpJustCreated, false)
	defineSingleKVTest("icmp almost timed out", icmpKey, icmpAlmostTimedOut, false)
	defineSingleKVTest("icmp timed out", icmpKey, icmpTimedOut, true)
}

func makeValue(created time.Duration, lastSeen time.Duration, legA conntrack.Leg, legB conntrack.Leg) conntrack.Value {
	return conntrack.NewValueNormal(created, lastSeen, 0, legA, legB)
}
