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

// bgp_helpers_test.go holds helpers shared by the BGP k8st suites (filter,
// advertisement and local-peer tests): creating/deleting Calico v3 BGP
// resources via the controller-runtime client, and matching routes in the
// in-cluster and external BIRD instances.

package k8stests

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/node/tests/k8st/utils"
)

// createV3 creates a Calico v3 object, failing the test on error.
func createV3(t testing.TB, cli ctrlclient.Client, obj ctrlclient.Object) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := cli.Create(ctx, obj); err != nil {
		t.Fatalf("creating %T %s: %v", obj, obj.GetName(), err)
	}
}

// deleteV3 best-effort removes a Calico v3 object; intended for cleanups, so it
// logs rather than fails on error.
func deleteV3(t testing.TB, cli ctrlclient.Client, obj ctrlclient.Object) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := cli.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
		t.Logf("WARNING: deleting %T %s: %v", obj, obj.GetName(), err)
	}
}

// setPeerFilters sets spec.filters on a BGPPeer, retrying on conflict. Mirrors
// _patch_peer_filters.
func setPeerFilters(t testing.TB, cli ctrlclient.Client, name string, filters []string) {
	t.Helper()
	err := utils.RetryUntilSuccess(t, 30*time.Second, func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		peer := &v3.BGPPeer{}
		if err := cli.Get(ctx, ctrlclient.ObjectKey{Name: name}, peer); err != nil {
			return err
		}
		peer.Spec.Filters = filters
		return cli.Update(ctx, peer)
	})
	if err != nil {
		t.Fatalf("patching filters on BGPPeer %s: %v", name, err)
	}
}

// birdPeerProtoName returns the BIRD protocol name for an in-cluster peering
// with the given peer IP, e.g. "Node_172_18_0_5" or "Global_2001_20__20".
func birdPeerProtoName(peerIP string, global bool) string {
	prefix := "Node_"
	if global {
		prefix = "Global_"
	}
	return prefix + strings.NewReplacer(".", "_", ":", "_").Replace(peerIP)
}

// clusterBirdHasRoute checks whether the in-cluster calico-node BIRD instance
// (in pod calicoPod) has the given route via peerIP, returning an error if the
// presence doesn't match `present`. Mirrors _check_route_in_cluster_bird.
func clusterBirdHasRoute(t testing.TB, calicoPod, route, peerIP string, ipv6, global, present bool) error {
	t.Helper()
	birdCmd := "birdcl"
	if ipv6 {
		birdCmd = "birdcl6"
	}
	proto := birdPeerProtoName(peerIP, global)
	out, err := utils.ExecInPod(t, "calico-system", calicoPod,
		fmt.Sprintf("%s show route protocol %s", birdCmd, proto),
		utils.RunOptions{AllowFail: true, SuppressErrLog: true})
	if err != nil {
		return fmt.Errorf("querying %s in pod %s: %w", birdCmd, calicoPod, err)
	}
	pattern := regexp.QuoteMeta(route) + ` *via ` + regexp.QuoteMeta(peerIP) + ` on .* \[` + proto
	return matchPresence(pattern, out, present)
}

// externalBirdHasRoute checks whether the external (plain docker container)
// BIRD instance has a route matching routeRegex via peerIPRegex on protocol
// birdPeer. routeRegex and peerIPRegex are treated as regular expressions, as
// in the Python original. Mirrors _check_route_in_external_bird.
func externalBirdHasRoute(t testing.TB, container, birdPeer, routeRegex, peerIPRegex string, ipv6, present bool) error {
	t.Helper()
	birdCmd := "birdcl"
	if ipv6 {
		birdCmd = "birdcl6"
	}
	out, err := utils.Run(t, fmt.Sprintf("docker exec %s %s show route protocol %s", container, birdCmd, birdPeer),
		utils.RunOptions{AllowFail: true, SuppressErrLog: true})
	if err != nil {
		return fmt.Errorf("querying %s in container %s: %w", birdCmd, container, err)
	}
	pattern := routeRegex + ` *via ` + peerIPRegex + ` on .* \[` + birdPeer
	return matchPresence(pattern, out, present)
}

// matchPresence reports whether pattern's match status in text equals the
// desired presence, returning a descriptive error otherwise.
func matchPresence(pattern, text string, present bool) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("compiling route regexp %q: %w", pattern, err)
	}
	matched := re.MatchString(text)
	if present && !matched {
		return fmt.Errorf("route not present when it should be (pattern %q)", pattern)
	}
	if !present && matched {
		return fmt.Errorf("route present when it should not be (pattern %q)", pattern)
	}
	return nil
}
