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
	"strings"
	"testing"
	"time"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils/iputils"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils/routeproto"
)

// Route is a parsed entry from `ip -j route show` as seen from the host
// network namespace of a calico-node pod.
type Route struct {
	Dst   string
	Dev   string
	Proto routeproto.Proto
	Raw   string
}

// GetNodeRoutes returns routes from the host routing table of the calico-node
// pod running on nodeName, filtered to those whose Dst contains dstMatch (empty
// matches all).
func GetNodeRoutes(t testing.TB, nodeName, dstMatch string) ([]Route, error) {
	t.Helper()
	routes, err := CalicoNodeIP(t, nodeName).Routes()
	if err != nil {
		return nil, err
	}
	return filterRoutes(routes, dstMatch), nil
}

func filterRoutes(in []iputils.Route, dstMatch string) []Route {
	rows := make([]Route, 0, len(in))
	for _, r := range in {
		if dstMatch != "" && !strings.Contains(r.Dst, dstMatch) {
			continue
		}
		raw, _ := json.Marshal(r)
		rows = append(rows, Route{
			Dst:   r.Dst,
			Dev:   r.Dev,
			Proto: routeproto.Parse(r.Protocol),
			Raw:   string(raw),
		})
	}
	return rows
}

// AssertRouteOwnership polls the kernel routing table on nodeName until at
// least one route matching dstSubstring carries the expected dev (if non-empty)
// and proto, fatally failing the test on timeout. The dev field is the empty
// string for direct next-hop (no-encap) routes since the actual device varies
// by cluster topology — for those, pass expectedDev="" to leave it unchecked.
func AssertRouteOwnership(t testing.TB, nodeName, dstSubstring, expectedDev string, expectedProto routeproto.Proto) {
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
