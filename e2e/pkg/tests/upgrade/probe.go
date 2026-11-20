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
	"bufio"
	"fmt"
	"maps"
	"net"
	"strconv"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/projectcalico/calico/e2e/pkg/utils/images"
)

const (
	probeLabel = "e2e-upgrade/probe"
	// warmupLines matching Before must be seen before seed hands over, so the
	// Before slice never judges the prober's own start-up.
	warmupLines = 10
	// windowPad absorbs clock skew between the CI runner, which records the
	// window, and the nodes, which stamp the probe lines.
	windowPad = 5 * time.Second
	afterSpan = 2 * time.Minute
	// maxGap is the longest silence a healthy prober can produce: one 2s
	// attempt, a 1s sleep, and scheduling slack.
	maxGap = 10 * time.Second
)

// proberDeployment builds the Deployment for p. client is the fixture Pod
// it impersonates.
func proberDeployment(namespace string, p Probe, client map[string]any) (*appsv1.Deployment, error) {
	_, host, port, err := parseTarget(p.Target)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(p.Target, "svc:") {
		host = host + "." + namespace + ".svc"
	} else if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil && ip.To4() == nil {
		host = "[" + ip.String() + "]"
	}

	check := fmt.Sprintf("nc -z -w1 %s %d", strings.Trim(host, "[]"), port)
	if p.Protocol == "http" {
		check = fmt.Sprintf("curl -sf -o /dev/null -m1 http://%s:%d/", host, port)
	}
	// One line per attempt, each a fresh connection, so a broken established
	// flow can't hide behind conntrack.
	script := `while :; do ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  if timeout 2 ` + check + ` >/dev/null 2>&1; then echo "$ts ok"; else echo "$ts fail"; fi
  sleep 1
done`

	podLabels := map[string]string{}
	if meta, ok := client["metadata"].(map[string]any); ok {
		if l, ok := meta["labels"].(map[string]any); ok {
			for k, v := range l {
				if s, ok := v.(string); ok {
					podLabels[k] = s
				}
			}
		}
	}
	podLabels[probeLabel] = p.Name
	sa := ""
	if spec, ok := client["spec"].(map[string]any); ok {
		sa, _ = spec["serviceAccountName"].(string)
	}

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "probe-" + p.Name, Namespace: namespace},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To[int32](1),
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{probeLabel: p.Name}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: maps.Clone(podLabels)},
				Spec: corev1.PodSpec{
					ServiceAccountName:            sa,
					TerminationGracePeriodSeconds: ptr.To[int64](1),
					Containers: []corev1.Container{{
						Name:            "probe",
						Image:           images.Netshoot,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Command:         []string{"bash", "-c", script},
						// Compatible with restricted PSA and OpenShift's restricted SCC
						// without pinning a UID the SCC would reject.
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: ptr.To(false),
							Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
							SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
						},
					}},
				},
			},
		},
	}, nil
}

type probeLine struct {
	at time.Time
	ok bool
}

func parseProbeLog(log string) ([]probeLine, error) {
	var out []probeLine
	sc := bufio.NewScanner(strings.NewReader(log))
	for sc.Scan() {
		ts, res, ok := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		if !ok {
			continue
		}
		at, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			return nil, fmt.Errorf("probe log line %q: %w", sc.Text(), err)
		}
		switch res {
		case "ok":
			out = append(out, probeLine{at, true})
		case "fail":
			out = append(out, probeLine{at, false})
		default:
			return nil, fmt.Errorf("probe log line %q: unknown result", sc.Text())
		}
	}
	return out, sc.Err()
}

// warmedUp returns the timestamp of the last line of the first run of
// warmupLines consecutive lines that satisfy st, or false if none yet.
func warmedUp(lines []probeLine, st State) (time.Time, bool) {
	run := 0
	for _, l := range lines {
		if st == Any || (st == Allowed) == l.ok {
			run++
			if run == warmupLines {
				return l.at, true
			}
		} else {
			run = 0
		}
	}
	return time.Time{}, false
}

// Inconclusive means the probe can't support a verdict either way.
type Inconclusive struct{ Reason string }

func (i *Inconclusive) Error() string { return "inconclusive: " + i.Reason }

// evaluate judges one probe's log. It returns the violations found, or an
// *Inconclusive error when the log can't be trusted.
func evaluate(lines []probeLine, p Probe, warmAt time.Time, w Window) ([]string, error) {
	type slice struct {
		name       string
		from, to   time.Time
		want       State
		lines      []probeLine
		seen, last bool
	}
	slices := []*slice{
		{name: "before", from: warmAt, to: w.Start.Add(-windowPad), want: p.Expect.Before},
		{name: "during", from: w.Start.Add(-windowPad), to: w.End.Add(p.Settle), want: p.Expect.During},
		{name: "after", from: w.End.Add(p.Settle), to: w.End.Add(p.Settle + afterSpan), want: p.Expect.After},
	}
	end := slices[2].to

	if len(lines) == 0 || lines[0].at.After(warmAt) {
		return nil, &Inconclusive{"the log no longer reaches back to the warm-up; it was rotated or the container restarted"}
	}
	var prev time.Time
	for _, l := range lines {
		if l.at.Before(warmAt) || !l.at.Before(end) {
			continue
		}
		if !prev.IsZero() && l.at.Sub(prev) > maxGap {
			return nil, &Inconclusive{fmt.Sprintf("no probe lines for %s after %s", l.at.Sub(prev), prev.Format(time.RFC3339))}
		}
		prev = l.at
		for _, s := range slices {
			if !l.at.Before(s.from) && l.at.Before(s.to) {
				s.lines = append(s.lines, l)
			}
		}
	}
	if !prev.IsZero() && end.Sub(prev) > maxGap {
		return nil, &Inconclusive{fmt.Sprintf("the log stops at %s, before the after-upgrade slice ends at %s", prev.Format(time.RFC3339), end.Format(time.RFC3339))}
	}

	var problems []string
	for _, s := range slices {
		if s.want == Any {
			continue
		}
		if len(s.lines) == 0 {
			return nil, &Inconclusive{fmt.Sprintf("no probe lines %s the upgrade (%s to %s)", s.name, s.from.Format(time.RFC3339), s.to.Format(time.RFC3339))}
		}
		switch s.want {
		case Denied:
			for _, l := range s.lines {
				if l.ok {
					problems = append(problems, fmt.Sprintf("probe %s: connected at %s %s the upgrade, where it must be denied", p.Name, l.at.Format(time.RFC3339), s.name))
					break
				}
			}
		case Allowed:
			run, worst, worstAt := 0, 0, time.Time{}
			for _, l := range s.lines {
				if l.ok {
					run = 0
					continue
				}
				if run++; run > worst {
					worst, worstAt = run, l.at
				}
			}
			if worst > p.MaxConsecutiveFails {
				problems = append(problems, fmt.Sprintf("probe %s: %d consecutive failed attempts ending %s %s the upgrade, more than the %d allowed",
					p.Name, worst, worstAt.Format(time.RFC3339), s.name, p.MaxConsecutiveFails))
			}
		}
	}
	return problems, nil
}

func formatCounts(lines []probeLine) string {
	ok := 0
	for _, l := range lines {
		if l.ok {
			ok++
		}
	}
	return strconv.Itoa(ok) + " ok / " + strconv.Itoa(len(lines)-ok) + " fail"
}
