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

package scenarios

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/onsi/ginkgo/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	"k8s.io/kubernetes/test/e2e/framework"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/tests/upgrade"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

//go:embed testdata/ipam-leak-and-live
var ipamLeakFS embed.FS

var (
	kccGVR        = schema.GroupVersionResource{Group: "projectcalico.org", Version: "v3", Resource: "kubecontrollersconfigurations"}
	ipamBlockGVR  = schema.GroupVersionResource{Group: "crd.projectcalico.org", Version: "v1", Resource: "ipamblocks"}
	ipamHandleGVR = schema.GroupVersionResource{Group: "crd.projectcalico.org", Version: "v1", Resource: "ipamhandles"}
)

const (
	leakHandlePrefix = "e2e-upgrade-ipam-leak-and-live-leak-"
	leakReleaseBy    = 6 * time.Minute
)

// An IP leaked on the old version must be released by the new version's GC,
// and live pods' allocations must survive the upgrade untouched.
//
// Seed turns GC off (leakGracePeriod 0s) so the old kube-controllers can't
// release the leak mid-upgrade; verify turns it back on.
func init() {
	upgrade.Register(upgrade.Scenario{
		Name:     "ipam-leak-and-live",
		Feature:  "IPAM",
		From:     []string{"v3.32", "v3.33"},
		Labels:   []any{describe.RequiresCalicoIPAM()},
		Serial:   true, // changes the cluster-wide leak grace period
		Fixtures: upgrade.Sub(ipamLeakFS, "testdata/ipam-leak-and-live"),
		Seed:     seedIPAMLeak,
		Verify:   verifyIPAMLeak,
		Restore:  restoreLeakGracePeriod,
	})
}

func restoreLeakGracePeriod(ctx context.Context, e *upgrade.Env) error {
	old, ok := e.Record.Values["oldLeakGracePeriod"]
	if !ok {
		return nil // seed stopped before changing it
	}
	return setLeakGracePeriod(ctx, e, old)
}

func seedIPAMLeak(ctx context.Context, e *upgrade.Env) error {
	live, err := livePodIPs(ctx, e)
	if err != nil {
		return err
	}
	ips, err := json.Marshal(live)
	if err != nil {
		return err
	}
	e.Record.Values["livePodIPs"] = string(ips)

	old, err := leakGracePeriod(ctx, e)
	if err != nil {
		return err
	}
	if old == "0s" {
		// Left by an earlier seed that never reached verify; restoring it
		// would leave GC off for good.
		old = ""
	}
	e.Record.Values["oldLeakGracePeriod"] = old
	if err := setLeakGracePeriod(ctx, e, "0s"); err != nil {
		return err
	}

	// Unique per seed, so re-seeding a dev cluster after a failed verify
	// doesn't collide with the earlier, still-unreleased leak.
	handle := fmt.Sprintf("%s%d", leakHandlePrefix, time.Now().Unix())
	ip, node, err := plantLeak(ctx, e, handle)
	if err != nil {
		return err
	}
	e.Record.Values["leakHandle"], e.Record.Values["leakIP"], e.Record.Values["leakNode"] = handle, ip, node
	framework.Logf("planted leaked IP %s on node %s under handle %s", ip, node, handle)
	return nil
}

func verifyIPAMLeak(ctx context.Context, e *upgrade.Env) error {
	handle := e.Record.Values["leakHandle"]
	ginkgo.By("Checking live pods kept their IPs")
	var want map[string]string
	if err := json.Unmarshal([]byte(e.Record.Values["livePodIPs"]), &want); err != nil {
		return fmt.Errorf("seed record livePodIPs: %w", err)
	}
	// Waiting keeps a readiness blip from reading as a lost IP.
	got, err := livePodIPs(ctx, e)
	if err != nil {
		return err
	}
	for pod, ip := range want {
		if got[pod] != ip {
			return fmt.Errorf("live pod %s had IP %s before the upgrade and has %q after", pod, ip, got[pod])
		}
	}

	// The normal suite's own IPAM GC spec may already have released the leak
	// with its 5s grace; either way master's GC must get there.
	ginkgo.By("Re-enabling GC and waiting for the leaked IP to be released")
	if err := setLeakGracePeriod(ctx, e, "2m"); err != nil {
		return err
	}
	cfg := apiconfig.NewCalicoAPIConfig()
	cfg.Spec.DatastoreType = apiconfig.Kubernetes
	cfg.Spec.Kubeconfig = framework.TestContext.KubeConfig
	lcgc, err := clientv3.New(*cfg)
	if err != nil {
		return fmt.Errorf("libcalico-go client: %w", err)
	}
	var lastErr error
	err = wait.PollUntilContextTimeout(ctx, 10*time.Second, leakReleaseBy, true, func(ctx context.Context) (bool, error) {
		ips, err := lcgc.IPAM().IPsByHandle(ctx, handle)
		var dne cerrors.ErrorResourceDoesNotExist
		if errors.As(err, &dne) || (err == nil && len(ips) == 0) {
			return true, nil
		}
		lastErr = fmt.Errorf("handle %s still holds %v (err %v)", handle, ips, err)
		return false, nil
	})
	if err != nil {
		return fmt.Errorf("leaked IP %s not released within %s of re-enabling GC: %w", e.Record.Values["leakIP"], leakReleaseBy, errors.Join(err, lastErr))
	}
	return nil
}

// livePodIPs maps each live pod to its IP once all three are Ready.
func livePodIPs(ctx context.Context, e *upgrade.Env) (map[string]string, error) {
	out := map[string]string{}
	poll := func(ctx context.Context) (bool, error) {
		if err := upgrade.PodsReady(ctx, e, "app=live"); err != nil {
			return false, nil
		}
		pods, err := e.Kube.CoreV1().Pods(e.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "app=live"})
		if err != nil {
			return false, nil
		}
		clear(out)
		for _, p := range pods.Items {
			out[p.Name] = p.Status.PodIP
		}
		return len(out) == 3, nil
	}
	if err := waitPoll(ctx, poll); err != nil {
		return nil, fmt.Errorf("waiting for 3 Ready live pods: %w", err)
	}
	return out, nil
}

func waitPoll(ctx context.Context, f wait.ConditionWithContextFunc) error {
	return wait.PollUntilContextTimeout(ctx, 2*time.Second, 3*time.Minute, true, f)
}

func leakGracePeriod(ctx context.Context, e *upgrade.Env) (string, error) {
	kcc, err := e.Dynamic.Resource(kccGVR).Get(ctx, "default", metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("reading KubeControllersConfiguration: %w", err)
	}
	v, _, _ := unstructured.NestedString(kcc.Object, "spec", "controllers", "node", "leakGracePeriod")
	return v, nil
}

// setLeakGracePeriod sets the value; "" removes it, restoring the default.
func setLeakGracePeriod(ctx context.Context, e *upgrade.Env, v string) error {
	var val any = v
	if v == "" {
		val = nil
	}
	patch, err := json.Marshal(map[string]any{"spec": map[string]any{"controllers": map[string]any{"node": map[string]any{"leakGracePeriod": val}}}})
	if err != nil {
		return err
	}
	_, err = e.Dynamic.Resource(kccGVR).Patch(ctx, "default", types.MergePatchType, patch, metav1.PatchOptions{})
	return err
}

// plantLeak records an allocation for a pod that doesn't exist, the way the
// IPAM client would, without using master's client on the old datastore.
// IPAM has no projectcalico.org/v3 API, hence the crd.projectcalico.org edit.
func plantLeak(ctx context.Context, e *upgrade.Env, handleID string) (ip, node string, err error) {
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		blocks, err := e.Dynamic.Resource(ipamBlockGVR).List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}
		for i := range blocks.Items {
			b := &blocks.Items[i]
			var ok bool
			if ip, node, ok, err = allocateGhost(b, e.Namespace, handleID); err != nil {
				return err
			}
			if !ok {
				continue
			}
			// Handle first, as the IPAM client does: a block entry whose handle
			// is missing can never be released.
			cidr, _, _ := unstructured.NestedString(b.Object, "spec", "cidr")
			handle := &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "crd.projectcalico.org/v1",
				"kind":       "IPAMHandle",
				"metadata":   map[string]any{"name": handleID},
				"spec":       map[string]any{"handleID": handleID, "block": map[string]any{cidr: int64(1)}, "deleted": false},
			}}
			if _, err := e.Dynamic.Resource(ipamHandleGVR).Create(ctx, handle, metav1.CreateOptions{}); err != nil {
				return err
			}
			if _, err := e.Dynamic.Resource(ipamBlockGVR).Update(ctx, b, metav1.UpdateOptions{}); err != nil {
				// A retry on conflict re-creates the handle, possibly for another block.
				if derr := e.Dynamic.Resource(ipamHandleGVR).Delete(ctx, handleID, metav1.DeleteOptions{}); derr != nil {
					return errors.Join(err, derr)
				}
				return err
			}
			return nil
		}
		return fmt.Errorf("no IPv4 IPAM block with a host affinity and a free address")
	})
	return ip, node, err
}

// allocateGhost takes the first free ordinal of an IPv4 host-affine block.
func allocateGhost(b *unstructured.Unstructured, ns, handleID string) (ip, node string, ok bool, err error) {
	spec, _, _ := unstructured.NestedMap(b.Object, "spec")
	affinity, _ := spec["affinity"].(string)
	cidrStr, _ := spec["cidr"].(string)
	unalloc, _ := spec["unallocated"].([]any)
	allocs, _ := spec["allocations"].([]any)
	attrs, _ := spec["attributes"].([]any)
	_, cidr, perr := net.ParseCIDR(cidrStr)
	if len(affinity) < 6 || affinity[:5] != "host:" || perr != nil || cidr.IP.To4() == nil || len(unalloc) == 0 {
		return "", "", false, nil
	}
	node = affinity[5:]
	ord, isInt := unalloc[0].(int64)
	if !isInt || ord < 0 || int(ord) >= len(allocs) {
		return "", "", false, fmt.Errorf("block %s: unexpected unallocated entry %v", cidrStr, unalloc[0])
	}

	allocs[ord] = int64(len(attrs))
	spec["allocations"] = allocs
	spec["unallocated"] = unalloc[1:]
	spec["attributes"] = append(attrs, map[string]any{
		"handle_id": handleID,
		"secondary": map[string]any{
			"namespace": ns,
			"pod":       "ghost",
			"node":      node,
			"timestamp": time.Now().UTC().Format("2006-01-02 15:04:05.999999999 -0700 MST"),
		},
	})
	// Newer blocks track per-allocation sequence numbers; these exceed 2^53,
	// so they must stay int64 end to end.
	if seq, ok := spec["sequenceNumber"].(int64); ok {
		perAlloc, _ := spec["sequenceNumberForAllocation"].(map[string]any)
		if perAlloc == nil {
			perAlloc = map[string]any{}
		}
		perAlloc[fmt.Sprint(ord)] = seq
		spec["sequenceNumberForAllocation"] = perAlloc
		spec["sequenceNumber"] = seq + 1
	}
	if err := unstructured.SetNestedMap(b.Object, spec, "spec"); err != nil {
		return "", "", false, err
	}

	addr := new(big.Int).Add(new(big.Int).SetBytes(cidr.IP.To4()), big.NewInt(ord))
	return net.IP(addr.FillBytes(make([]byte, 4))).String(), node, true, nil
}
