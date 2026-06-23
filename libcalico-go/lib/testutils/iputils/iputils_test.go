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

package iputils

import (
	"fmt"
	"strings"
	"testing"
)

// fakeRunner returns canned output and records the args it was asked to run.
// The keys are the `ip ...` command lines (minus the leading "ip").
type fakeRunner struct {
	out      map[string]string
	err      error
	lastArgs []string
}

func (f *fakeRunner) ExecOutput(args ...string) (string, error) {
	f.lastArgs = args
	if f.err != nil {
		return "", f.err
	}
	// args[0] is always "ip"; key on the remainder.
	key := strings.Join(args[1:], " ")
	out, ok := f.out[key]
	if !ok {
		return "", fmt.Errorf("fakeRunner: no canned output for %q", key)
	}
	return out, nil
}

func TestAddrShow(t *testing.T) {
	const loAddr = `[{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],` +
		`"mtu":65536,"operstate":"UNKNOWN","link_type":"loopback","address":"00:00:00:00:00:00",` +
		`"addr_info":[{"family":"inet","local":"172.17.0.3","prefixlen":16,"scope":"global","label":"eth0"}]}]`

	r := &fakeRunner{out: map[string]string{
		"-j -4 addr show dev eth0 scope global": loAddr,
	}}

	links, err := New(r).V4().AddrShow("dev", "eth0", "scope", "global")
	if err != nil {
		t.Fatalf("AddrShow: %v", err)
	}
	if len(links) != 1 {
		t.Fatalf("expected 1 link, got %d", len(links))
	}
	if links[0].IfName != "lo" {
		t.Errorf("ifname = %q, want lo", links[0].IfName)
	}
	if !links[0].HasFlag("UP") {
		t.Errorf("expected UP flag in %v", links[0].Flags)
	}
	if len(links[0].AddrInfo) != 1 {
		t.Fatalf("expected 1 addr_info, got %d", len(links[0].AddrInfo))
	}
	a := links[0].AddrInfo[0]
	if got := a.CIDR(); got != "172.17.0.3/16" {
		t.Errorf("CIDR = %q, want 172.17.0.3/16", got)
	}
	n, err := a.Network()
	if err != nil {
		t.Fatalf("Network: %v", err)
	}
	if got := n.String(); got != "172.17.0.0/16" {
		t.Errorf("Network = %q, want 172.17.0.0/16", got)
	}
}

func TestLinkShowDevDetailed(t *testing.T) {
	const wg = `[{"ifindex":7,"ifname":"wireguard.cali","flags":["POINTOPOINT","NOARP","UP","LOWER_UP"],` +
		`"mtu":1440,"operstate":"UNKNOWN","link_type":"none","linkinfo":{"info_kind":"wireguard"}}]`

	r := &fakeRunner{out: map[string]string{
		"-j -d link show dev wireguard.cali": wg,
	}}

	link, err := New(r).Detailed().LinkShowDev("wireguard.cali")
	if err != nil {
		t.Fatalf("LinkShowDev: %v", err)
	}
	if link.MTU != 1440 {
		t.Errorf("MTU = %d, want 1440", link.MTU)
	}
	if link.Kind() != "wireguard" {
		t.Errorf("Kind = %q, want wireguard", link.Kind())
	}
	if !link.HasFlag("NOARP") {
		t.Errorf("expected NOARP flag in %v", link.Flags)
	}
}

func TestRouteGet(t *testing.T) {
	const route = `[{"dst":"10.65.0.2","dev":"cali123","prefsrc":"10.65.0.1","protocol":"kernel","scope":"link","flags":[]}]`

	r := &fakeRunner{out: map[string]string{
		"-j route get 10.65.0.2": route,
	}}

	routes, err := New(r).RouteGet("10.65.0.2")
	if err != nil {
		t.Fatalf("RouteGet: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}
	if routes[0].Dev != "cali123" {
		t.Errorf("Dev = %q, want cali123", routes[0].Dev)
	}
	if routes[0].Dst != "10.65.0.2" {
		t.Errorf("Dst = %q, want 10.65.0.2", routes[0].Dst)
	}
}

func TestRouteProto(t *testing.T) {
	cases := []struct {
		protocol string
		want     RouteProto
		wantStr  string
	}{
		{"", RouteProtoUnknown, "unknown"},
		{"bird", RouteProtoBIRD, "bird"},
		{"80", RouteProtoFelix, "felix"},
		{"12", RouteProtoBIRD, "bird"},
		{"42", RouteProto(42), "proto-42"},
		{"bogus", RouteProtoUnknown, "unknown"},
	}
	for _, c := range cases {
		got := Route{Protocol: c.protocol}.Proto()
		if got != c.want {
			t.Errorf("Route{Protocol:%q}.Proto() = %d, want %d", c.protocol, got, c.want)
		}
		if got.String() != c.wantStr {
			t.Errorf("RouteProto(%d).String() = %q, want %q", got, got.String(), c.wantStr)
		}
	}
}

func TestNeighAndRuleShow(t *testing.T) {
	r := &fakeRunner{out: map[string]string{
		"-j neigh show": `[{"dst":"10.65.1.3","dev":"eth20","lladdr":"ee:ee:ee:ee:ee:ee","state":["PERMANENT"]}]`,
		"-j rule show":  `[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"}]`,
	}}

	neighs, err := New(r).NeighShow()
	if err != nil {
		t.Fatalf("NeighShow: %v", err)
	}
	if len(neighs) != 1 || neighs[0].LLAddr != "ee:ee:ee:ee:ee:ee" {
		t.Errorf("unexpected neighs: %+v", neighs)
	}

	rules, err := New(r).RuleShow()
	if err != nil {
		t.Fatalf("RuleShow: %v", err)
	}
	if len(rules) != 2 || rules[1].Table != "main" {
		t.Errorf("unexpected rules: %+v", rules)
	}
}

// TestEmptyOutput verifies that an empty (rather than "[]") response decodes to
// an empty slice without error — some `ip` versions print nothing for an empty
// result.
func TestEmptyOutput(t *testing.T) {
	r := &fakeRunner{out: map[string]string{
		"-j -4 route show to 10.65.0.2 table all dev cali123": "  \n",
	}}

	routes, err := New(r).V4().Routes(
		WithDestination("10.65.0.2"),
		WithTable("all"),
		WithDevice("cali123"),
	)
	if err != nil {
		t.Fatalf("Routes: %v", err)
	}
	if len(routes) != 0 {
		t.Errorf("expected no routes, got %+v", routes)
	}
}
