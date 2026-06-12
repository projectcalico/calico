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

package utils

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

// RouteProto identifies the netlink protocol that owns a kernel route. The
// numeric values match the kernel's RTPROT_* constants. Felix-programmed
// routes carry protocol 80 (felix/dataplane/linux/dataplanedefs.DefaultRouteProto);
// BIRD-programmed routes carry protocol 12 (RTPROT_BIRD).
type RouteProto int

const (
	RouteProtoUnknown RouteProto = -1
	RouteProtoBIRD    RouteProto = 12
	RouteProtoFelix   RouteProto = 80
)

func (p RouteProto) String() string {
	switch p {
	case RouteProtoBIRD:
		return "bird"
	case RouteProtoFelix:
		return "felix"
	case RouteProtoUnknown:
		return "unknown"
	}
	return fmt.Sprintf("proto-%d", int(p))
}

// Route is a parsed entry from `ip -j route show` as seen from the host
// network namespace of a calico-node pod.
type Route struct {
	Dst   string
	Dev   string
	Proto RouteProto
	Raw   string
}

// jsonRoute is the on-the-wire form emitted by `ip -j route show`. Protocol is
// a string in iproute2's JSON output regardless of whether the kernel proto has
// a name in /etc/iproute2/rt_protos: named protos appear as e.g. "bird";
// unnamed appear as the decimal value (e.g. "80").
type jsonRoute struct {
	Dst      string `json:"dst"`
	Dev      string `json:"dev"`
	Protocol string `json:"protocol"`
}

// GetNodeRoutes returns routes from the host routing table of the calico-node
// pod running on nodeName, filtered to those whose Dst contains dstMatch (empty
// matches all).
func GetNodeRoutes(t testing.TB, nodeName, dstMatch string) ([]Route, error) {
	t.Helper()
	out, err := ExecInCalicoNode(t, nodeName, "ip -j route show")
	if err != nil {
		return nil, err
	}
	return parseRoutes(out, dstMatch)
}

func parseRoutes(out, dstMatch string) ([]Route, error) {
	var parsed []jsonRoute
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		return nil, fmt.Errorf("parsing `ip -j route show` output: %w (output: %s)", err, out)
	}
	rows := make([]Route, 0, len(parsed))
	for _, jr := range parsed {
		if dstMatch != "" && !strings.Contains(jr.Dst, dstMatch) {
			continue
		}
		raw, _ := json.Marshal(jr)
		rows = append(rows, Route{
			Dst:   jr.Dst,
			Dev:   jr.Dev,
			Proto: parseProto(jr.Protocol),
			Raw:   string(raw),
		})
	}
	return rows, nil
}

func parseProto(s string) RouteProto {
	switch s {
	case "":
		return RouteProtoUnknown
	case "bird":
		return RouteProtoBIRD
	}
	if n, err := strconv.Atoi(s); err == nil {
		return RouteProto(n)
	}
	return RouteProtoUnknown
}

// AssertRouteOwnership polls the kernel routing table on nodeName until at
// least one route matching dstSubstring carries the expected dev (if non-empty)
// and proto, fatally failing the test on timeout. The dev field is the empty
// string for direct next-hop (no-encap) routes since the actual device varies
// by cluster topology — for those, pass expectedDev="" to leave it unchecked.
func AssertRouteOwnership(t testing.TB, nodeName, dstSubstring, expectedDev string, expectedProto RouteProto) {
	t.Helper()
	t.Logf("Asserting routes for %q on node %s use dev=%q proto=%s",
		dstSubstring, nodeName, expectedDev, expectedProto)
	err := RetryUntilSuccess(t, 60*time.Second, func() error {
		routes, err := GetNodeRoutes(t, nodeName, dstSubstring)
		if err != nil {
			return err
		}
		if len(routes) == 0 {
			return fmt.Errorf("no routes found containing %q on node %s", dstSubstring, nodeName)
		}
		for _, r := range routes {
			if expectedDev != "" && r.Dev != expectedDev {
				continue
			}
			if r.Proto == expectedProto {
				return nil
			}
		}
		return fmt.Errorf("no route on node %s with dev=%q proto=%s found among %v",
			nodeName, expectedDev, expectedProto, routes)
	})
	if err != nil {
		t.Fatalf("route ownership assertion failed: %v", err)
	}
}
