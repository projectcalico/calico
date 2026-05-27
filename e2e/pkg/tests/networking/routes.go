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

package networking

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/onsi/ginkgo/v2"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
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
	Dst     string
	Gateway string
	Dev     string
	Proto   RouteProto
	Raw     string
}

// GetNodeRoutes returns routes from the host routing table of the calico-node
// pod running on nodeName. If dstMatch is non-empty, only routes whose Dst
// contains it (as a substring) are returned. Parses the JSON output of
// `ip -j route show` so callers can assert on the route protocol owner.
func GetNodeRoutes(cli ctrlclient.Client, nodeName, dstMatch string) []Route {
	pod := findCalicoNodePod(cli, nodeName)
	out, err := conncheck.ExecInPod(pod, "sh", "-c", "ip -j route show")
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error running 'ip -j route show' in pod %s", pod.Name)

	return parseRoutes(out, dstMatch)
}

// HasRouteProto returns true if the slice contains a route with the given proto.
// Useful as an Eventually predicate when waiting for a route ownership change.
func HasRouteProto(routes []Route, proto RouteProto) bool {
	for _, r := range routes {
		if r.Proto == proto {
			return true
		}
	}
	return false
}

// AllRoutesProto returns true if every route in the slice carries the given
// proto. Returns false on an empty slice.
func AllRoutesProto(routes []Route, proto RouteProto) bool {
	if len(routes) == 0 {
		return false
	}
	for _, r := range routes {
		if r.Proto != proto {
			return false
		}
	}
	return true
}

// findCalicoNodePod locates the calico-node pod on the given node. If nodeName
// is empty, returns the first calico-node pod found.
func findCalicoNodePod(cli ctrlclient.Client, nodeName string) *corev1.Pod {
	pods := corev1.PodList{}
	err := cli.List(context.Background(), &pods, ctrlclient.MatchingLabels{"k8s-app": "calico-node"})
	ExpectWithOffset(2, err).NotTo(HaveOccurred(), "Error querying calico-node pods")
	ExpectWithOffset(2, pods.Items).NotTo(BeEmpty(), "No calico-node pods found")
	if nodeName == "" {
		return &pods.Items[0]
	}
	for i := range pods.Items {
		if pods.Items[i].Spec.NodeName == nodeName {
			return &pods.Items[i]
		}
	}
	ExpectWithOffset(2, false).To(BeTrue(), "No calico-node pod found on node %s", nodeName)
	return nil
}

// jsonRoute is the on-the-wire form emitted by `ip -j route show`.
// Protocol is a string in iproute2's JSON output regardless of whether the
// kernel proto has a name in /etc/iproute2/rt_protos: named protos appear as
// e.g. "bird"; unnamed appear as the decimal value (e.g. "80").
type jsonRoute struct {
	Dst      string `json:"dst"`
	Gateway  string `json:"gateway"`
	Dev      string `json:"dev"`
	Protocol string `json:"protocol"`
}

func parseRoutes(out, dstMatch string) []Route {
	var parsed []jsonRoute
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		ExpectWithOffset(2, err).NotTo(HaveOccurred(), "Failed to parse `ip -j route show` output: %s", out)
		return nil
	}
	rows := make([]Route, 0, len(parsed))
	for _, jr := range parsed {
		if dstMatch != "" && !strings.Contains(jr.Dst, dstMatch) {
			continue
		}
		raw, _ := json.Marshal(jr)
		rows = append(rows, Route{
			Dst:     jr.Dst,
			Gateway: jr.Gateway,
			Dev:     jr.Dev,
			Proto:   parseProto(jr.Protocol),
			Raw:     string(raw),
		})
	}
	return rows
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

// expectedClusterRouteProto returns the route protocol owner that the cluster
// is currently configured to use for IPIP and no-encap cluster routes.
// "Felix" => proto 80, anything else (including unset) => BIRD's proto 12.
func expectedClusterRouteProto(cli ctrlclient.Client) RouteProto {
	fc := v3.NewFelixConfiguration()
	Expect(cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, fc)).
		To(Succeed(), "Error querying FelixConfiguration")
	if fc.Spec.ProgramClusterRoutes != nil &&
		*fc.Spec.ProgramClusterRoutes == "Enabled" {
		return RouteProtoFelix
	}
	return RouteProtoBIRD
}

// assertRouteOwnership polls the kernel routing table on nodeName until at
// least one route matching dstSubstring carries the expected dev (if
// non-empty) and proto. The dev field is the empty string for direct
// next-hop (no-encap) routes since the actual device varies by cluster
// topology — for those, dev is left unchecked and only the proto byte
// matters.
func assertRouteOwnership(cli ctrlclient.Client, nodeName, dstSubstring, expectedDev string, expectedProto RouteProto) {
	ginkgo.By(fmt.Sprintf("Asserting routes for %q on node %s use dev=%q proto=%s",
		dstSubstring, nodeName, expectedDev, expectedProto))
	Eventually(func() error {
		routes := GetNodeRoutes(cli, nodeName, dstSubstring)
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
	}, 60*time.Second, 2*time.Second).Should(Succeed())
}
