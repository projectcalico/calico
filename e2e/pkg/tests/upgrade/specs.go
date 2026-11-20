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

package upgrade

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/restmapper"
	"k8s.io/kubernetes/test/e2e/framework"
	admissionapi "k8s.io/pod-security-admission/api"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/testconfig"
	"github.com/projectcalico/calico/e2e/pkg/utils"
)

const (
	seedTimeout    = 10 * time.Minute
	verifyTimeout  = 20 * time.Minute
	warmupTimeout  = 2 * time.Minute
	restoreTimeout = time.Minute
)

// declareSpecs adds the scenario's two specs to the ginkgo tree. They run in
// separate invocations, on either side of the upgrade, so nothing but the
// cluster carries state between them.
func declareSpecs(s *Scenario) {
	var decorators []any
	for _, f := range s.From {
		decorators = append(decorators, framework.WithLabel(testconfig.UpgradeFromLabel(f)))
	}
	decorators = append(decorators, s.Labels...)
	if s.Serial {
		decorators = append(decorators, describe.WithSerial())
	}

	describe.CalicoDescribe(
		describe.WithTeam(describe.Core),
		describe.WithFeature(s.Feature),
		fmt.Sprintf("[upgrade] %s", s.Name),
		func() {
			f := utils.NewDefaultFramework("e2e-upgrade")
			// The scenario owns a fixed namespace that must outlive this process.
			f.SkipNamespaceCreation = true

			// Per-scenario decorators go on an inner container because the
			// labels lint wants WithFeature as a literal CalicoDescribe argument.
			framework.Context(append(decorators, "scenario", func() {
				framework.It("seed", framework.WithLabel(testconfig.UpgradeSeedLabel), func(ctx context.Context) {
					ctx, cancel := context.WithTimeout(ctx, seedTimeout)
					defer cancel()
					e := newEnv(ctx, f, s)
					framework.ExpectNoError(runSeed(ctx, s, e), "seeding upgrade scenario %s", s.Name)
				})

				framework.It("verify", framework.WithLabel(testconfig.UpgradeVerifyLabel), func(ctx context.Context) {
					ctx, cancel := context.WithTimeout(ctx, verifyTimeout)
					defer cancel()
					e := newEnv(ctx, f, s)
					framework.ExpectNoError(runVerify(ctx, s, e), "verifying upgrade scenario %s", s.Name)
				})
			})...)
		},
	)
}

func newEnv(ctx context.Context, f *framework.Framework, s *Scenario) *Env {
	calicoNS, err := calicoNamespace(ctx, f.ClientSet)
	framework.ExpectNoError(err, "finding the Calico namespace")
	return &Env{
		Namespace:       s.Namespace(),
		CalicoNamespace: calicoNS,
		Kube:            f.ClientSet,
		Dynamic:         f.DynamicClient,
		Mapper:          restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(f.ClientSet.Discovery())),
	}
}

func runSeed(ctx context.Context, s *Scenario, e *Env) error {
	ginkgo.By("Recreating namespace " + e.Namespace)
	if err := recreateNamespace(ctx, e); err != nil {
		return err
	}

	ginkgo.By("Applying fixtures")
	rec := &Record{
		SeededAt:    time.Now().UTC(),
		FromVersion: calicoVersion(ctx, e),
		ProberUIDs:  map[string]string{},
		ProbeWarmAt: map[string]time.Time{},
		Values:      map[string]string{},
	}
	e.Record = rec
	refs, err := s.applyFixtures(ctx, e)
	rec.Objects = refs
	if err != nil {
		return err
	}

	if len(s.Probes) > 0 {
		ginkgo.By("Starting probers")
		if err := startProbers(ctx, s, e); err != nil {
			return err
		}
	}

	if s.Seed != nil {
		ginkgo.By("Running the scenario's seed step")
		if err := s.Seed(ctx, e); err != nil {
			return restoreAfter(ctx, s, e, fmt.Errorf("seed step: %w", err))
		}
	}

	ginkgo.By("Writing the seed record")
	// No record means verify never runs Restore, so seed must.
	if err := writeRecord(ctx, e.Kube, e.Namespace, rec); err != nil {
		return restoreAfter(ctx, s, e, err)
	}
	return nil
}

func restoreAfter(ctx context.Context, s *Scenario, e *Env, err error) error {
	if s.Restore == nil {
		return err
	}
	// The seed may have failed because its context expired, and Restore must
	// still get to run.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), restoreTimeout)
	defer cancel()
	if rerr := s.Restore(rctx, e); rerr != nil {
		return errors.Join(err, fmt.Errorf("restore: %w", rerr))
	}
	return err
}

func recreateNamespace(ctx context.Context, e *Env) error {
	nsAPI := e.Kube.CoreV1().Namespaces()
	if err := nsAPI.Delete(ctx, e.Namespace, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("deleting stale namespace: %w", err)
	}
	if err := wait.PollUntilContextTimeout(ctx, 2*time.Second, 3*time.Minute, true, func(ctx context.Context) (bool, error) {
		_, err := nsAPI.Get(ctx, e.Namespace, metav1.GetOptions{})
		return apierrors.IsNotFound(err), nil
	}); err != nil {
		return fmt.Errorf("waiting for stale namespace %s to go: %w", e.Namespace, err)
	}
	privileged := string(admissionapi.LevelPrivileged)
	_, err := nsAPI.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: e.Namespace,
		Labels: map[string]string{
			admissionapi.EnforceLevelLabel: privileged,
			admissionapi.AuditLevelLabel:   privileged,
			admissionapi.WarnLevelLabel:    privileged,
		},
	}}, metav1.CreateOptions{})
	return err
}

// calicoVersion is informational: it shows in the record which build the
// state was seeded on.
func calicoVersion(ctx context.Context, e *Env) string {
	for _, gv := range []string{"crd.projectcalico.org/v1", "projectcalico.org/v3"} {
		gvr := schema.GroupVersionResource{Group: strings.Split(gv, "/")[0], Version: strings.Split(gv, "/")[1], Resource: "clusterinformations"}
		ci, err := e.Dynamic.Resource(gvr).Get(ctx, "default", metav1.GetOptions{})
		if err != nil {
			continue
		}
		if v, ok, _ := unstructured.NestedString(ci.Object, "spec", "calicoVersion"); ok {
			return v
		}
	}
	return "unknown"
}

func startProbers(ctx context.Context, s *Scenario, e *Env) error {
	objs, err := s.fixtureObjects()
	if err != nil {
		return err
	}
	pods := map[string]map[string]any{}
	for _, o := range objs {
		if o.GetKind() == "Pod" {
			pods[o.GetName()] = o.Object
		}
	}

	// A dead target satisfies a Denied probe, so the targets must be serving
	// before any line counts.
	for _, svc := range probeServices(s.Probes) {
		if err := waitForEndpoints(ctx, e, svc); err != nil {
			return err
		}
	}

	for _, p := range s.Probes {
		d, err := proberDeployment(e.Namespace, p, pods[p.Client])
		if err != nil {
			return err
		}
		if _, err := e.Kube.AppsV1().Deployments(e.Namespace).Create(ctx, d, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("creating prober %s: %w", p.Name, err)
		}
	}

	for _, p := range s.Probes {
		var lastErr error
		err := wait.PollUntilContextTimeout(ctx, 2*time.Second, warmupTimeout, true, func(ctx context.Context) (bool, error) {
			pod, err := proberPod(ctx, e, p)
			if err != nil {
				lastErr = err
				return false, nil
			}
			lines, err := proberLines(ctx, e, pod)
			if err != nil {
				lastErr = err
				return false, nil
			}
			at, ok := warmedUp(lines, p.Expect.Before)
			if !ok {
				lastErr = fmt.Errorf("prober %s: no %d consecutive %s lines yet (%s)", p.Name, warmupLines, p.Expect.Before, formatCounts(lines))
				return false, nil
			}
			e.Record.ProberUIDs[p.Name] = string(pod.UID)
			e.Record.ProbeWarmAt[p.Name] = at
			return true, nil
		})
		if err != nil {
			return fmt.Errorf("prober %s never settled into its before-upgrade state: %w", p.Name, errors.Join(err, lastErr))
		}
	}
	return nil
}

func probeServices(probes []Probe) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range probes {
		kind, host, _, err := parseTarget(p.Target)
		if err == nil && kind == "svc" && !seen[host] {
			seen[host] = true
			out = append(out, host)
		}
	}
	return out
}

func waitForEndpoints(ctx context.Context, e *Env, svc string) error {
	return wait.PollUntilContextTimeout(ctx, 2*time.Second, 3*time.Minute, true, func(ctx context.Context) (bool, error) {
		slices, err := e.Kube.DiscoveryV1().EndpointSlices(e.Namespace).List(ctx, metav1.ListOptions{
			LabelSelector: discoveryv1.LabelServiceName + "=" + svc,
		})
		if err != nil {
			return false, nil
		}
		for _, sl := range slices.Items {
			for _, ep := range sl.Endpoints {
				if ep.Conditions.Ready != nil && *ep.Conditions.Ready {
					return true, nil
				}
			}
		}
		return false, nil
	})
}

// proberPod returns the single pod of p's Deployment.
func proberPod(ctx context.Context, e *Env, p Probe) (*corev1.Pod, error) {
	pods, err := e.Kube.CoreV1().Pods(e.Namespace).List(ctx, metav1.ListOptions{LabelSelector: probeLabel + "=" + p.Name})
	if err != nil {
		return nil, err
	}
	var live []corev1.Pod
	for _, pod := range pods.Items {
		if pod.DeletionTimestamp == nil {
			live = append(live, pod)
		}
	}
	if len(live) != 1 {
		return nil, fmt.Errorf("prober %s has %d pods, want 1", p.Name, len(live))
	}
	return &live[0], nil
}

func proberLines(ctx context.Context, e *Env, pod *corev1.Pod) ([]probeLine, error) {
	raw, err := e.Kube.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &corev1.PodLogOptions{Container: "probe"}).DoRaw(ctx)
	if err != nil {
		return nil, err
	}
	return parseProbeLog(string(raw))
}

func runVerify(ctx context.Context, s *Scenario, e *Env) error {
	ginkgo.By("Reading the seed record and the upgrade window")
	rec, err := readRecord(ctx, e.Kube, e.Namespace)
	if err != nil {
		return err
	}
	e.Record = rec
	if s.Restore != nil {
		ginkgo.DeferCleanup(func(ctx context.Context) {
			if err := s.Restore(ctx, e); err != nil {
				framework.Fail(fmt.Sprintf("restoring cluster-wide state after scenario %s: %v", s.Name, err))
			}
		})
	}
	w, err := readWindow(ctx, e.Kube)
	if err != nil {
		return err
	}
	e.Record, e.Window = rec, w
	if w.Failed {
		framework.Logf("WARNING: the upgrade window records a failed upgrade; results describe a cluster that didn't finish upgrading")
	}

	// Only clean up a pass: a failure's state is the evidence.
	ginkgo.DeferCleanup(func(ctx context.Context) {
		if ginkgo.CurrentSpecReport().Failed() {
			framework.Logf("keeping namespace %s and the scenario's cluster-scoped fixtures for diagnosis", e.Namespace)
			return
		}
		if err := deleteClusterScoped(ctx, e, rec.Objects); err != nil {
			framework.Logf("WARNING: deleting cluster-scoped fixtures: %v", err)
		}
		if err := e.Kube.CoreV1().Namespaces().Delete(ctx, e.Namespace, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			framework.Logf("WARNING: deleting namespace %s: %v", e.Namespace, err)
		}
	})

	if len(s.Probes) > 0 {
		if err := waitForAfterSlices(ctx, s, w); err != nil {
			return err
		}
		ginkgo.By("Judging the probe logs")
		var problems []string
		var unjudged []error
		for _, p := range s.Probes {
			ps, err := judgeProbe(ctx, e, p, rec)
			if err != nil {
				// One untrustworthy log mustn't hide another probe's violation.
				unjudged = append(unjudged, fmt.Errorf("probe %s: %w", p.Name, err))
				continue
			}
			problems = append(problems, ps...)
		}
		gomega.Expect(problems).To(gomega.BeEmpty(), "connectivity broke the scenario's expectations around the upgrade (unjudged probes: %v)", errors.Join(unjudged...))
		if len(unjudged) > 0 {
			return errors.Join(unjudged...)
		}
	}

	ginkgo.By("Running the scenario's verify step")
	return s.Verify(ctx, e)
}

// waitForAfterSlices holds verify until every probe's after-upgrade slice has
// been logged. Verify can start before then because it runs alongside the
// rest of the post-upgrade suite.
func waitForAfterSlices(ctx context.Context, s *Scenario, w Window) error {
	var until time.Time
	for _, p := range s.Probes {
		if t := w.End.Add(p.Settle + afterSpan + windowPad); t.After(until) {
			until = t
		}
	}
	d := time.Until(until)
	if d <= 0 {
		return nil
	}
	ginkgo.By(fmt.Sprintf("Waiting %s for the after-upgrade probe slices to complete", d.Round(time.Second)))
	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func judgeProbe(ctx context.Context, e *Env, p Probe, rec *Record) ([]string, error) {
	pod, err := proberPod(ctx, e, p)
	if err != nil {
		return nil, &Inconclusive{err.Error()}
	}
	if want := rec.ProberUIDs[p.Name]; string(pod.UID) != want {
		return nil, &Inconclusive{fmt.Sprintf("prober pod %s replaced the one seeded (uid %s); it was rescheduled or evicted", pod.Name, want)}
	}
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.RestartCount > 0 {
			return nil, &Inconclusive{fmt.Sprintf("prober container restarted %d times; the API no longer returns its earlier log", cs.RestartCount)}
		}
	}
	lines, err := proberLines(ctx, e, pod)
	if err != nil {
		return nil, err
	}
	framework.Logf("probe %s on node %s: %s overall", p.Name, pod.Spec.NodeName, formatCounts(lines))
	return evaluate(lines, p, rec.ProbeWarmAt[p.Name], e.Window)
}
