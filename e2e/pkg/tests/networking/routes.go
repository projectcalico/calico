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
	"strings"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils/iputils"
)

// GetNodeRoutes returns routes from the host routing table of the calico-node
// pod running on nodeName. If dstMatch is non-empty, only routes whose Dst
// contains it (as a substring) are returned. Parses the JSON output of
// `ip -j route show` so callers can assert on the route protocol owner.
func GetNodeRoutes(cli ctrlclient.Client, nodeName, dstMatch string) []iputils.Route {
	pod := findCalicoNodePod(cli, nodeName)
	routes, err := podIP(pod).Routes()
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error running 'ip -j route show' in pod %s", pod.Name)

	return filterRoutes(routes, dstMatch)
}

// podIP returns an iputils.IP that runs the `ip` utility inside pod via
// `kubectl exec`, so tests can query routes as typed structs instead of
// scraping text.
func podIP(pod *corev1.Pod) *iputils.IP {
	return iputils.New(podIPRunner{pod: pod})
}

// podIPRunner adapts conncheck.ExecInPod to the iputils.Runner interface.
// iputils passes the command as separate args; ExecInPod runs them via
// `sh -c`, so joining is safe for `ip` invocations (whose args never contain
// spaces).
type podIPRunner struct {
	pod *corev1.Pod
}

func (r podIPRunner) ExecOutput(args ...string) (string, error) {
	return conncheck.ExecInPod(r.pod, "sh", "-c", strings.Join(args, " "))
}

// HasRouteProto returns true if the slice contains a route with the given proto.
// Useful as an Eventually predicate when waiting for a route ownership change.
func HasRouteProto(routes []iputils.Route, proto iputils.RouteProto) bool {
	for _, r := range routes {
		if r.Proto() == proto {
			return true
		}
	}
	return false
}

// AllRoutesProto returns true if every route in the slice carries the given
// proto. Returns false on an empty slice.
func AllRoutesProto(routes []iputils.Route, proto iputils.RouteProto) bool {
	if len(routes) == 0 {
		return false
	}
	for _, r := range routes {
		if r.Proto() != proto {
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

// filterRoutes keeps only the routes whose Dst contains dstMatch; an empty
// dstMatch returns every route.
func filterRoutes(in []iputils.Route, dstMatch string) []iputils.Route {
	if dstMatch == "" {
		return in
	}
	rows := make([]iputils.Route, 0, len(in))
	for _, r := range in {
		if strings.Contains(r.Dst, dstMatch) {
			rows = append(rows, r)
		}
	}
	return rows
}

// expectedClusterRouteProto returns the route protocol owner that the cluster
// is currently configured to use for IPIP and no-encap cluster routes.
// "Felix" => proto 80, anything else (including unset) => BIRD's proto 12.
func expectedClusterRouteProto(cli ctrlclient.Client) iputils.RouteProto {
	fc := v3.NewFelixConfiguration()
	Expect(cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, fc)).
		To(Succeed(), "Error querying FelixConfiguration")
	if fc.Spec.ProgramClusterRoutes != nil &&
		*fc.Spec.ProgramClusterRoutes == "Enabled" {
		return iputils.RouteProtoFelix
	}
	return iputils.RouteProtoBIRD
}
