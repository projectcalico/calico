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

package conntrack

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf/conntrack/timeouts"
	ctv4 "github.com/projectcalico/calico/felix/bpf/conntrack/v4"
	"github.com/projectcalico/calico/felix/timeshim/mocktime"
)

// A forged RST on a flow Linux conntrack carries must not get its entry reaped,
// or it runs uncounted.
func TestLivenessScannerRSTReapWaitsForLinuxConntrack(t *testing.T) {
	now := mocktime.StartKTime
	key := NewKey(ProtoTCP, net.ParseIP("10.65.1.2").To4(), 15300, net.ParseIP("172.17.0.8").To4(), 8055)
	entry := func(flags uint32, idle time.Duration) Value {
		v := NewValueNormal(now-idle, flags,
			Leg{SynSeen: true, AckSeen: true, Opener: true},
			Leg{SynSeen: true, AckSeen: true})
		binary.LittleEndian.PutUint64(v[ctv4.VoRSTSeen:ctv4.VoRSTSeen+8], uint64(now-idle))
		return v
	}

	for _, tc := range []struct {
		name        string
		flags       uint32
		idle        time.Duration
		held        bool
		err         error
		wantDelete  bool
		wantLookups int
	}{
		{"Linux still holds it", ctv4.FlagConnLimitOut, 3 * time.Minute, true, nil, false, 1},
		{"Linux has dropped it", ctv4.FlagConnLimitOut, 3 * time.Minute, false, nil, true, 1},
		{"lookup fails", ctv4.FlagConnLimitOut, 3 * time.Minute, false, errors.New("netlink failed"), false, 1},
		{"idle past TCPEstablished", ctv4.FlagConnLimitOut, 2 * time.Hour, true, nil, true, 0},
		{"no connection limit", 0, 3 * time.Minute, true, nil, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookups := 0
			ls := NewLivenessScanner(timeouts.DefaultTimeouts(), false,
				WithTimeShim(mocktime.New()),
				WithLinuxConntrack(func(KeyInterface, ValueInterface) (bool, error) {
					lookups++
					return tc.held, tc.err
				}))

			verdict, _ := ls.Check(key, entry(tc.flags, tc.idle), nil)
			if got := verdict == ScanVerdictDelete; got != tc.wantDelete {
				t.Errorf("deleted=%v, want %v", got, tc.wantDelete)
			}
			if lookups != tc.wantLookups {
				t.Errorf("%d Linux lookups, want %d", lookups, tc.wantLookups)
			}
		})
	}
}

func TestParseCTTCPState(t *testing.T) {
	tuple := nl.NewRtAttr(unix.NLA_F_NESTED|nl.CTA_TUPLE_ORIG, nil)
	tuple.AddChild(nl.NewRtAttr(unix.NLA_F_NESTED|nl.CTA_TUPLE_IP, nil))
	protoInfo := nl.NewRtAttr(unix.NLA_F_NESTED|nl.CTA_PROTOINFO, nil)
	tcp := nl.NewRtAttr(unix.NLA_F_NESTED|nl.CTA_PROTOINFO_TCP, nil)
	tcp.AddChild(nl.NewRtAttr(nl.CTA_PROTOINFO_TCP_STATE, []byte{nl.TCP_CONNTRACK_CLOSE_WAIT}))
	protoInfo.AddChild(tcp)

	msg := (&nl.Nfgenmsg{NfgenFamily: nl.FAMILY_V4, Version: nl.NFNETLINK_V0}).Serialize()
	msg = append(msg, tuple.Serialize()...)
	msg = append(msg, protoInfo.Serialize()...)

	state, err := parseCTTCPState(msg)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if state != nl.TCP_CONNTRACK_CLOSE_WAIT {
		t.Errorf("state %d, want CLOSE_WAIT", state)
	}

	if _, err := parseCTTCPState(msg[:nl.SizeofNfgenmsg]); err == nil {
		t.Error("a message without protoinfo parsed without error")
	}
}

// A half-closed flow can still carry data, so it holds its slot as the BPF
// recount would.
func TestTCPStateBeforeClose(t *testing.T) {
	for state, want := range map[uint8]bool{
		nl.TCP_CONNTRACK_SYN_RECV:    true,
		nl.TCP_CONNTRACK_ESTABLISHED: true,
		nl.TCP_CONNTRACK_FIN_WAIT:    true,
		nl.TCP_CONNTRACK_CLOSE_WAIT:  true,
		nl.TCP_CONNTRACK_LAST_ACK:    false,
		nl.TCP_CONNTRACK_TIME_WAIT:   false,
		nl.TCP_CONNTRACK_CLOSE:       false,
	} {
		if got := tcpStateBeforeClose(state); got != want {
			t.Errorf("state %d: before close=%v, want %v", state, got, want)
		}
	}
}
