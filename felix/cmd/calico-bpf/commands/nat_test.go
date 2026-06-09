// Copyright (c) 2020-2024 Tigera, Inc. All rights reserved.
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

package commands

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"

	nat2 "github.com/projectcalico/calico/felix/bpf/nat"
)

func TestNATDump(t *testing.T) {
	nat := nat2.MapMem{
		nat2.NewNATKey(net.IPv4(1, 1, 1, 1), 80, 6):   nat2.NewNATValue(35, 2, 0, 0),
		nat2.NewNATKey(net.IPv4(2, 1, 1, 1), 553, 17): nat2.NewNATValue(107, 1, 0, 0),
		nat2.NewNATKey(net.IPv4(3, 1, 1, 1), 553, 17): nat2.NewNATValue(108, 1, 0, 0),
	}

	back := nat2.BackendMapMem{
		nat2.NewNATBackendKey(35, 0):  nat2.NewNATBackendValue(net.IPv4(5, 5, 5, 5), 8080),
		nat2.NewNATBackendKey(35, 1):  nat2.NewNATBackendValue(net.IPv4(6, 6, 6, 6), 8080),
		nat2.NewNATBackendKey(108, 0): nat2.NewNATBackendValue(net.IPv4(3, 3, 3, 3), 553),
	}

	dumpNice(func(format string, i ...any) { fmt.Printf(format, i...) }, nat, back, false)
}

// TestMaglevDumpJSON checks that makeMaglevJSON flattens the maglev map into
// (svc, ordinal) -> backend entries, sorted deterministically, and that the
// result marshals to JSON.
func TestMaglevDumpJSON(t *testing.T) {
	m := nat2.MaglevMapMem{
		nat2.NewMaglevBackendKey(35, 1): nat2.NewNATBackendValue(net.IPv4(6, 6, 6, 6), 8080),
		nat2.NewMaglevBackendKey(35, 0): nat2.NewNATBackendValue(net.IPv4(5, 5, 5, 5), 8080),
		nat2.NewMaglevBackendKey(12, 0): nat2.NewNATBackendValue(net.IPv4(7, 7, 7, 7), 90),
	}

	entries := makeMaglevJSON(m)

	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d: %+v", len(entries), entries)
	}
	// Sorted by (svc, ordinal): (12,0), (35,0), (35,1).
	if entries[0].SvcID != 12 || entries[1].SvcID != 35 || entries[1].Ordinal != 0 || entries[2].Ordinal != 1 {
		t.Fatalf("entries not sorted by (svc, ordinal): %+v", entries)
	}
	if entries[1].Addr != "5.5.5.5" || entries[1].Port != 8080 {
		t.Fatalf("unexpected backend for (35,0): %+v", entries[1])
	}
	if _, err := json.Marshal(entries); err != nil {
		t.Fatalf("marshal: %v", err)
	}
}

// TestAffinityDumpJSON checks that makeAffinityJSON exposes the client, the
// frontend service tuple, and the chosen backend as structured fields.
func TestAffinityDumpJSON(t *testing.T) {
	m := nat2.AffinityMapMem{
		nat2.NewAffinityKey(net.IPv4(10, 0, 0, 1), nat2.NewNATKey(net.IPv4(1, 1, 1, 1), 80, 6)): nat2.NewAffinityValue(
			0, nat2.NewNATBackendValue(net.IPv4(5, 5, 5, 5), 8080)),
	}

	entries := makeAffinityJSON(m)

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d: %+v", len(entries), entries)
	}
	e := entries[0]
	if e.ClientIP != "10.0.0.1" || e.Addr != "1.1.1.1" || e.Port != 80 || e.Proto != 6 {
		t.Fatalf("unexpected affinity key fields: %+v", e)
	}
	if e.Backend.Addr != "5.5.5.5" || e.Backend.Port != 8080 {
		t.Fatalf("unexpected backend: %+v", e.Backend)
	}
	if _, err := json.Marshal(entries); err != nil {
		t.Fatalf("marshal: %v", err)
	}
}

// TestDumpNiceGrouping verifies that dumpNiceGrouped groups frontends sharing the
// same service ID so the backend list is printed just once per service.
func TestDumpNiceGrouping(t *testing.T) {
	natMap := nat2.MapMem{
		// Two frontends sharing service id=35 (e.g. ClusterIP + NodePort).
		nat2.NewNATKey(net.IPv4(1, 1, 1, 1), 80, 6):  nat2.NewNATValue(35, 2, 0, 0),
		nat2.NewNATKey(net.IPv4(10, 0, 0, 1), 80, 6): nat2.NewNATValue(35, 2, 0, 0),
		// Unrelated service.
		nat2.NewNATKey(net.IPv4(2, 1, 1, 1), 553, 17): nat2.NewNATValue(107, 1, 0, 0),
	}
	back := nat2.BackendMapMem{
		nat2.NewNATBackendKey(35, 0):  nat2.NewNATBackendValue(net.IPv4(5, 5, 5, 5), 8080),
		nat2.NewNATBackendKey(35, 1):  nat2.NewNATBackendValue(net.IPv4(6, 6, 6, 6), 8080),
		nat2.NewNATBackendKey(107, 0): nat2.NewNATBackendValue(net.IPv4(7, 7, 7, 7), 553),
	}

	var output strings.Builder
	dumpNiceGrouped(func(format string, i ...any) { fmt.Fprintf(&output, format, i...) }, natMap, back)

	out := output.String()

	// The backend IPs for service 35 should each appear exactly once.
	if c := strings.Count(out, "5.5.5.5"); c != 1 {
		t.Errorf("expected 5.5.5.5 exactly once, got %d times in:\n%s", c, out)
	}
	if c := strings.Count(out, "6.6.6.6"); c != 1 {
		t.Errorf("expected 6.6.6.6 exactly once, got %d times in:\n%s", c, out)
	}

	// Both frontends for service 35 should be present.
	if !strings.Contains(out, "1.1.1.1") {
		t.Errorf("expected 1.1.1.1 in output, got:\n%s", out)
	}
	if !strings.Contains(out, "10.0.0.1") {
		t.Errorf("expected 10.0.0.1 in output, got:\n%s", out)
	}

	// The unrelated service should also be present.
	if !strings.Contains(out, "2.1.1.1") {
		t.Errorf("expected 2.1.1.1 in output, got:\n%s", out)
	}
	if !strings.Contains(out, "7.7.7.7") {
		t.Errorf("expected 7.7.7.7 in output, got:\n%s", out)
	}
}

// TestFilterByServiceID verifies that filterByServiceID returns exactly the
// frontends that share the same service ID as the requested key, including
// additional frontends that point to the same backend set.
func TestFilterByServiceID(t *testing.T) {
	natMap := nat2.MapMem{
		// Two frontends sharing service id=35 (e.g. ClusterIP + NodePort for same svc).
		nat2.NewNATKey(net.IPv4(1, 1, 1, 1), 80, 6):  nat2.NewNATValue(35, 2, 0, 0),
		nat2.NewNATKey(net.IPv4(10, 0, 0, 1), 80, 6): nat2.NewNATValue(35, 2, 0, 0),
		// Unrelated frontend with a different service id.
		nat2.NewNATKey(net.IPv4(2, 1, 1, 1), 553, 17): nat2.NewNATValue(107, 1, 0, 0),
	}

	back := nat2.BackendMapMem{
		nat2.NewNATBackendKey(35, 0):  nat2.NewNATBackendValue(net.IPv4(5, 5, 5, 5), 8080),
		nat2.NewNATBackendKey(35, 1):  nat2.NewNATBackendValue(net.IPv4(6, 6, 6, 6), 8080),
		nat2.NewNATBackendKey(107, 0): nat2.NewNATBackendValue(net.IPv4(7, 7, 7, 7), 553),
	}

	// Filter by the first frontend – should return both id=35 entries.
	filterKey := nat2.NewNATKey(net.IPv4(1, 1, 1, 1), 80, 6)
	filtered, err := filterByServiceID(natMap, filterKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(filtered) != 2 {
		t.Errorf("expected 2 frontends with service id=35, got %d", len(filtered))
	}

	var output strings.Builder
	dumpNice(func(format string, i ...any) { fmt.Fprintf(&output, format, i...) }, filtered, back, false)

	out := output.String()
	if !strings.Contains(out, "1.1.1.1") {
		t.Errorf("expected 1.1.1.1 in filtered output, got:\n%s", out)
	}
	if !strings.Contains(out, "10.0.0.1") {
		t.Errorf("expected 10.0.0.1 in filtered output, got:\n%s", out)
	}
	if strings.Contains(out, "2.1.1.1") {
		t.Errorf("did not expect 2.1.1.1 in filtered output, got:\n%s", out)
	}
}

// TestFilterByServiceIDNotFound verifies that filterByServiceID returns an
// error when the requested frontend key is not present in the map.
func TestFilterByServiceIDNotFound(t *testing.T) {
	natMap := nat2.MapMem{
		nat2.NewNATKey(net.IPv4(1, 1, 1, 1), 80, 6): nat2.NewNATValue(35, 1, 0, 0),
	}

	missing := nat2.NewNATKey(net.IPv4(9, 9, 9, 9), 8080, 6)
	_, err := filterByServiceID(natMap, missing)
	if err == nil {
		t.Fatal("expected an error for a missing frontend key, got nil")
	}
}

// TestParseIPPortProto verifies that parseIPPortProto handles string protocol
// names ("tcp", "udp") as well as numeric protocol values.
func TestParseIPPortProto(t *testing.T) {
	cases := []struct {
		args      []string
		wantProto uint8
		wantErr   bool
	}{
		{[]string{"1.2.3.4", "80", "tcp"}, 6, false},
		{[]string{"1.2.3.4", "53", "udp"}, 17, false},
		{[]string{"1.2.3.4", "80", "6"}, 6, false},
		{[]string{"1.2.3.4", "53", "17"}, 17, false},
		{[]string{"not-an-ip", "80", "tcp"}, 0, true},
		{[]string{"1.2.3.4", "99999", "tcp"}, 0, true},
		{[]string{"1.2.3.4", "80", "bogus"}, 0, true},
	}

	for _, tc := range cases {
		ip, port, proto, err := parseIPPortProto(tc.args)
		if tc.wantErr {
			if err == nil {
				t.Errorf("args=%v: expected error, got ip=%v port=%d proto=%d", tc.args, ip, port, proto)
			}
			continue
		}
		if err != nil {
			t.Errorf("args=%v: unexpected error: %v", tc.args, err)
			continue
		}
		if proto != tc.wantProto {
			t.Errorf("args=%v: proto: got %d, want %d", tc.args, proto, tc.wantProto)
		}
	}
}
