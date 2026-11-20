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
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

var t0 = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

// pattern builds one line a second from t0: 'o' ok, 'x' fail, '.' no line.
func pattern(p string) []probeLine {
	var out []probeLine
	for i, c := range p {
		if c == '.' {
			continue
		}
		out = append(out, probeLine{at: t0.Add(time.Duration(i) * time.Second), ok: c == 'o'})
	}
	return out
}

func repeat(c string, n int) string { return strings.Repeat(c, n) }

// A 3-minute log: warm-up at 10s, upgrade from 60s to 120s, settle 5s, and
// the 2-minute after slice ends at 245s.
func testWindow() (time.Time, Window) {
	return t0.Add(10 * time.Second), Window{Start: t0.Add(60 * time.Second), End: t0.Add(120 * time.Second)}
}

func testProbe(e Expect) Probe {
	return Probe{Name: "p", Expect: e, MaxConsecutiveFails: 2, Settle: 5 * time.Second}
}

func TestEvaluate(t *testing.T) {
	warm, w := testWindow()
	for _, tc := range []struct {
		name         string
		log          string
		expect       Expect
		problems     int
		inconclusive bool
	}{
		{"steady allowed", repeat("o", 250), AlwaysAllowed, 0, false},
		{"two-attempt blip is tolerated", repeat("o", 90) + "xx" + repeat("o", 158), AlwaysAllowed, 0, false},
		{"three-attempt outage fails", repeat("o", 90) + "xxx" + repeat("o", 157), AlwaysAllowed, 1, false},
		{"steady denied", repeat("x", 250), AlwaysDenied, 0, false},
		{"one success is a fail-open", repeat("x", 100) + "o" + repeat("x", 149), AlwaysDenied, 1, false},
		{"denied after, anything during", repeat("o", 70) + repeat("x", 180), Expect{Allowed, Any, Denied}, 0, false},
		{"still allowed after", repeat("o", 250), Expect{Allowed, Any, Denied}, 1, false},
		{"outage during counts against during only", repeat("o", 80) + repeat("x", 20) + repeat("o", 150), Expect{Allowed, Any, Allowed}, 0, false},
		{"gap means inconclusive", repeat("o", 100) + repeat(".", 15) + repeat("o", 135), AlwaysAllowed, 0, true},
		{"log ends early", repeat("o", 200), AlwaysAllowed, 0, true},
		{"log starts after warm-up (rotated)", repeat(".", 20) + repeat("o", 230), AlwaysAllowed, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			problems, err := evaluate(pattern(tc.log), testProbe(tc.expect), warm, w)
			var inc *Inconclusive
			if tc.inconclusive {
				if !errors.As(err, &inc) {
					t.Fatalf("got problems=%v err=%v, want inconclusive", problems, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(problems) != tc.problems {
				t.Fatalf("got %d problems %v, want %d", len(problems), problems, tc.problems)
			}
		})
	}
}

func TestWarmedUp(t *testing.T) {
	lines := pattern("xxooooooooo" + "ooo")
	at, ok := warmedUp(lines, Allowed)
	if !ok || !at.Equal(t0.Add(11*time.Second)) {
		t.Fatalf("warmedUp = %v, %v; want the 10th consecutive ok at +11s", at, ok)
	}
	if _, ok := warmedUp(pattern("ooooxoooooo"), Allowed); ok {
		t.Fatal("a broken run must not count as warm")
	}
	if _, ok := warmedUp(pattern("oxoxoxoxox"), Any); !ok {
		t.Fatal("Any accepts every line")
	}
}

func TestParseProbeLog(t *testing.T) {
	lines, err := parseProbeLog("2026-11-20T12:00:00Z ok\n2026-11-20T12:00:01Z fail\n\n")
	if err != nil || len(lines) != 2 || !lines[0].ok || lines[1].ok {
		t.Fatalf("parseProbeLog = %v, %v", lines, err)
	}
	if _, err := parseProbeLog("2026-11-20T12:00:00Z maybe\n"); err == nil {
		t.Fatal("unknown result accepted")
	}
}

func TestParseTarget(t *testing.T) {
	for _, tc := range []struct {
		in, kind, host string
		port           int
		bad            bool
	}{
		{in: "svc:srv:80", kind: "svc", host: "srv", port: 80},
		{in: "ip:10.0.0.1:443", kind: "ip", host: "10.0.0.1", port: 443},
		{in: "ip:[fd00::1]:443", kind: "ip", host: "[fd00::1]", port: 443},
		{in: "pod:x:80", bad: true},
		{in: "svc:Srv:80", bad: true},
		{in: "svc:srv", bad: true},
		{in: "ip:nope:80", bad: true},
	} {
		kind, host, port, err := parseTarget(tc.in)
		if tc.bad {
			if err == nil {
				t.Errorf("parseTarget(%q) accepted", tc.in)
			}
			continue
		}
		if err != nil || kind != tc.kind || host != tc.host || port != tc.port {
			t.Errorf("parseTarget(%q) = %q %q %d %v", tc.in, kind, host, port, err)
		}
	}
}

const (
	clientPod = `apiVersion: v1
kind: Pod
metadata:
  name: cli
  labels: {app: cli}
spec:
  serviceAccountName: cli-sa
  containers: [{name: c, image: x}]
`
	serverSvc = `apiVersion: v1
kind: Service
metadata: {name: srv}
spec:
  selector: {app: srv}
  ports: [{port: 80}]
`
)

func validScenario(files map[string]string, probes ...Probe) Scenario {
	fsys := fstest.MapFS{}
	for k, v := range files {
		fsys[k] = &fstest.MapFile{Data: []byte(v)}
	}
	return Scenario{
		Name: "demo", Feature: "NetworkPolicy", From: []string{"v3.33"},
		Fixtures: fsys, Probes: probes,
		Verify: func(context.Context, *Env) error { return nil },
	}
}

func TestValidate(t *testing.T) {
	allowed := Probe{Name: "a", Client: "cli", Target: "svc:srv:80", Protocol: "tcp", Expect: AlwaysAllowed}
	denied := Probe{Name: "d", Client: "cli", Target: "svc:srv:81", Protocol: "tcp", Expect: AlwaysDenied}
	base := map[string]string{"cli.yaml": clientPod, "srv.yaml": serverSvc}

	for _, tc := range []struct {
		name string
		s    Scenario
		want string
	}{
		{"valid", validScenario(base, allowed, denied), ""},
		{"denied without a positive control", validScenario(base, denied), "positive control"},
		{"unknown client", validScenario(base, Probe{Name: "a", Client: "nope", Target: "svc:srv:80", Protocol: "tcp", Expect: AlwaysAllowed}), "not a fixture Pod"},
		{"empty expect", validScenario(base, Probe{Name: "a", Client: "cli", Target: "svc:srv:80", Protocol: "tcp"}), "checks nothing"},
		{"duplicate probe", validScenario(base, allowed, allowed), "unique"},
		{"foreign namespace", validScenario(map[string]string{"cli.yaml": strings.Replace(clientPod, "name: cli\n", "name: cli\n  namespace: default\n", 1)}), "leave it empty"},
		{"service selects client", validScenario(map[string]string{"cli.yaml": clientPod, "srv.yaml": strings.Replace(serverSvc, "app: srv", "app: cli", 1)}, allowed), "selects client pod"},
		{"unscoped GNP", validScenario(map[string]string{"gnp.yaml": "apiVersion: projectcalico.org/v3\nkind: GlobalNetworkPolicy\nmetadata: {name: e2e-upgrade-demo-gnp}\nspec: {selector: all()}\n"}), "namespaceSelector"},
		{"GNP excluding the scenario namespace", validScenario(map[string]string{"gnp.yaml": "apiVersion: projectcalico.org/v3\nkind: GlobalNetworkPolicy\nmetadata: {name: e2e-upgrade-demo-gnp}\nspec: {selector: all(), namespaceSelector: \"projectcalico.org/name != 'e2e-upgrade-demo'\"}\n"}), "namespaceSelector"},
		{"GNP pinned to the scenario namespace", validScenario(map[string]string{"gnp.yaml": "apiVersion: projectcalico.org/v3\nkind: GlobalNetworkPolicy\nmetadata: {name: e2e-upgrade-demo-gnp}\nspec: {selector: all(), namespaceSelector: \"projectcalico.org/name == 'e2e-upgrade-demo'\"}\n"}), ""},
		{"bad feature", func() Scenario { s := validScenario(base); s.Feature = "Nope"; return s }(), "feature"},
		{"bad stream", func() Scenario { s := validScenario(base); s.From = []string{"3.33"}; return s }(), "want vX.Y"},
		{"no verify", func() Scenario { s := validScenario(base); s.Verify = nil; return s }(), "verify is nil"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.s.validate()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("validate: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validate = %v, want error containing %q", err, tc.want)
			}
		})
	}
}

// The prober must look like its client to policy, and not to its Service.
func TestProberDeployment(t *testing.T) {
	s := validScenario(map[string]string{"cli.yaml": clientPod})
	objs, err := s.fixtureObjects()
	if err != nil {
		t.Fatal(err)
	}
	d, err := proberDeployment("e2e-upgrade-demo", Probe{Name: "a", Target: "svc:srv:80", Protocol: "http"}, objs[0].Object)
	if err != nil {
		t.Fatal(err)
	}
	pt := d.Spec.Template
	if pt.Labels["app"] != "cli" || pt.Labels[probeLabel] != "a" || pt.Spec.ServiceAccountName != "cli-sa" {
		t.Fatalf("prober doesn't impersonate cli: labels %v sa %q", pt.Labels, pt.Spec.ServiceAccountName)
	}
	script := strings.Join(pt.Spec.Containers[0].Command, " ")
	if !strings.Contains(script, "http://srv.e2e-upgrade-demo.svc:80/") {
		t.Fatalf("script doesn't target the service: %s", script)
	}
}
