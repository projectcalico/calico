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

	dumpNice(func(format string, i ...any) { fmt.Printf(format, i...) }, nat, back)
}

// TestDumpNiceGrouping verifies that dumpNice groups frontends sharing the
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
	dumpNice(func(format string, i ...any) { fmt.Fprintf(&output, format, i...) }, natMap, back)

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
	dumpNice(func(format string, i ...any) { fmt.Fprintf(&output, format, i...) }, filtered, back)

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
