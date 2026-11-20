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

// Package upgrade runs upgrade scenarios: state seeded on the old cluster,
// connectivity probed throughout the upgrade, and checks run afterwards. See
// README.md for how to add one.
package upgrade

import (
	"context"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/e2e/pkg/describe"
)

// State is what a probe must see during one slice of the run.
type State int

const (
	Any State = iota
	Allowed
	Denied
)

func (s State) String() string {
	return [...]string{"Any", "Allowed", "Denied"}[s]
}

// Expect gives a probe's required State before, during and after the upgrade.
type Expect struct{ Before, During, After State }

var (
	AlwaysAllowed = Expect{Allowed, Allowed, Allowed}
	AlwaysDenied  = Expect{Denied, Denied, Denied}
)

const (
	defaultMaxConsecutiveFails = 2
	defaultSettle              = 60 * time.Second
)

// Probe is a connection attempted once a second, from a prober pod that
// impersonates Client, for the whole life of the scenario.
type Probe struct {
	// Name is DNS-1123; the prober Deployment is probe-<Name>.
	Name string
	// Client is the fixture Pod whose labels and service account the prober
	// copies, so policy treats it as that client.
	Client string
	// Target is "svc:<name>:<port>", a Service in the scenario namespace
	// resolved by DNS on every attempt, or "ip:<addr>:<port>".
	Target   string
	Protocol string // "tcp" or "http"
	Expect   Expect
	// MaxConsecutiveFails bounds an outage in an Allowed slice. It counts
	// attempts, not seconds: one failed attempt alone can take 3s.
	MaxConsecutiveFails int
	// Settle is how long after the upgrade the After slice starts.
	Settle time.Duration
}

// Window is the upgrade as CI recorded it.
type Window struct {
	Start, End time.Time
	Failed     bool
}

// Env is what Seed and Verify get.
type Env struct {
	Namespace string
	// CalicoNamespace is where calico-node runs: calico-system for operator
	// installs, kube-system for manifests.
	CalicoNamespace string
	Kube            kubernetes.Interface
	Dynamic         dynamic.Interface
	Mapper          meta.RESTMapper
	// Record is writable in Seed and persisted after it returns; in Verify it
	// is what Seed persisted.
	Record *Record
	// Window is zero in Seed.
	Window Window
}

// Scenario is one upgrade test. Register it from an init function.
type Scenario struct {
	Name    string
	Feature string
	// From lists the RELEASE_STREAM values the fixtures are valid on.
	From []string
	// Labels are extra describe.* decorators that let lanes exclude it.
	Labels []any
	// Serial runs both specs alone; required when the scenario changes
	// cluster-wide behaviour.
	Serial   bool
	Fixtures fs.FS
	Probes   []Probe
	Seed     func(ctx context.Context, e *Env) error
	Verify   func(ctx context.Context, e *Env) error
	// Restore undoes cluster-wide changes Seed made. It runs when seeding
	// fails, and after verify whether or not verify got as far as Verify, so
	// an early failure can't leave the rest of the job on a patched config.
	// It must cope with Seed having stopped part-way.
	Restore func(ctx context.Context, e *Env) error
}

// Namespace is the namespace holding the scenario's namespaced state.
func (s *Scenario) Namespace() string { return "e2e-upgrade-" + s.Name }

var (
	registryMu sync.Mutex
	registry   = map[string]*Scenario{}
	dns1123    = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	streamRE   = regexp.MustCompile(`^(v[0-9]+\.[0-9]+|master)$`)
)

// Register validates s and declares its seed and verify specs. It panics on an
// invalid scenario so the mistake fails the build's unit tests, not a CI run.
func Register(s Scenario) {
	sc := s
	if err := sc.validate(); err != nil {
		panic(fmt.Sprintf("upgrade scenario %q: %v", s.Name, err))
	}
	registryMu.Lock()
	if _, dup := registry[sc.Name]; dup {
		registryMu.Unlock()
		panic(fmt.Sprintf("upgrade scenario %q registered twice", sc.Name))
	}
	registry[sc.Name] = &sc
	registryMu.Unlock()
	declareSpecs(&sc)
}

// Registered returns the registered scenarios, sorted by name.
func Registered() []*Scenario {
	registryMu.Lock()
	defer registryMu.Unlock()
	out := make([]*Scenario, 0, len(registry))
	for _, s := range registry {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Scenario) validate() error {
	// Leave room for the "e2e-upgrade-" prefix in a 63-character namespace.
	if !dns1123.MatchString(s.Name) || len(s.Name) > 50 {
		return fmt.Errorf("name must be DNS-1123 and at most 50 characters")
	}
	if !describe.IsFeature(s.Feature) {
		return fmt.Errorf("feature %q is not in describe's feature list", s.Feature)
	}
	if len(s.From) == 0 {
		return fmt.Errorf("from is empty")
	}
	for _, f := range s.From {
		if !streamRE.MatchString(f) {
			return fmt.Errorf("from stream %q: want vX.Y", f)
		}
	}
	if s.Verify == nil {
		return fmt.Errorf("verify is nil")
	}
	for i := range s.Probes {
		p := &s.Probes[i]
		if p.MaxConsecutiveFails == 0 {
			p.MaxConsecutiveFails = defaultMaxConsecutiveFails
		}
		if p.Settle == 0 {
			p.Settle = defaultSettle
		}
	}

	objs, err := s.fixtureObjects()
	if err != nil {
		return err
	}
	return s.validateFixtures(objs)
}

// validateFixtures enforces the rules that keep a scenario's state from
// leaking into the rest of the suite and its probes from passing vacuously.
func (s *Scenario) validateFixtures(objs []*unstructured.Unstructured) error {
	pods := map[string]map[string]string{}
	for _, o := range objs {
		if ns := o.GetNamespace(); ns != "" && ns != s.Namespace() {
			return fmt.Errorf("fixture %s/%s names namespace %q; leave it empty", o.GetKind(), o.GetName(), ns)
		}
		if o.GetKind() == "Pod" {
			pods[o.GetName()] = o.GetLabels()
		}
		if err := s.checkPolicyScope(o); err != nil {
			return err
		}
	}

	names := map[string]bool{}
	clients := map[string]map[string]string{}
	allowedIn := map[string][3]bool{}
	deniedIn := map[string][3]bool{}
	for _, p := range s.Probes {
		if !dns1123.MatchString(p.Name) || names[p.Name] {
			return fmt.Errorf("probe name %q must be unique and DNS-1123", p.Name)
		}
		names[p.Name] = true
		if _, ok := pods[p.Client]; !ok {
			return fmt.Errorf("probe %s: client %q is not a fixture Pod", p.Name, p.Client)
		}
		clients[p.Client] = pods[p.Client]
		if p.Protocol != "tcp" && p.Protocol != "http" {
			return fmt.Errorf("probe %s: protocol %q: want tcp or http", p.Name, p.Protocol)
		}
		if p.Expect == (Expect{}) {
			return fmt.Errorf("probe %s: expect checks nothing", p.Name)
		}
		kind, host, _, err := parseTarget(p.Target)
		if err != nil {
			return fmt.Errorf("probe %s: %w", p.Name, err)
		}
		if kind != "svc" {
			continue
		}
		a, d := allowedIn[host], deniedIn[host]
		for i, st := range []State{p.Expect.Before, p.Expect.During, p.Expect.After} {
			a[i] = a[i] || st == Allowed
			d[i] = d[i] || st == Denied
		}
		allowedIn[host], deniedIn[host] = a, d
	}

	// A Denied probe against a target that is down passes; an Allowed probe to
	// the same Service in the same slice proves the target was up.
	slices := [3]string{"before", "during", "after"}
	for host, d := range deniedIn {
		for i := range d {
			if d[i] && !allowedIn[host][i] {
				return fmt.Errorf("service %s is expected Denied %s the upgrade with no Allowed probe to it in that slice as a positive control", host, slices[i])
			}
		}
	}

	// A fixture Service selecting a client would put probers in its endpoints.
	for _, o := range objs {
		if o.GetKind() != "Service" {
			continue
		}
		sel, _, _ := unstructured.NestedStringMap(o.Object, "spec", "selector")
		if len(sel) == 0 {
			continue
		}
		for name, lbls := range clients {
			if labels.SelectorFromSet(sel).Matches(labels.Set(lbls)) {
				return fmt.Errorf("service %s selects client pod %s; probers copying its labels would join the service", o.GetName(), name)
			}
		}
	}
	return nil
}

// checkPolicyScope keeps cluster-scoped policy fixtures from changing what the
// normal suite sees while it runs between seed and verify.
func (s *Scenario) checkPolicyScope(o *unstructured.Unstructured) error {
	switch o.GetKind() {
	case "GlobalNetworkPolicy", "StagedGlobalNetworkPolicy":
		// An exact equality, because a substring match also passes a negation
		// ("!=") or a longer namespace name sharing this prefix.
		sel, _, _ := unstructured.NestedString(o.Object, "spec", "namespaceSelector")
		pinned := false
		for _, key := range []string{"projectcalico.org/name", "kubernetes.io/metadata.name"} {
			for _, q := range []string{"'", `"`} {
				pinned = pinned || strings.TrimSpace(sel) == key+" == "+q+s.Namespace()+q
			}
		}
		if !pinned {
			return fmt.Errorf("fixture %s %s: spec.namespaceSelector must select only namespace %s", o.GetKind(), o.GetName(), s.Namespace())
		}
	case "ClusterNetworkPolicy":
		const nsLabel = "kubernetes.io/metadata.name"
		byNS, _, _ := unstructured.NestedString(o.Object, "spec", "subject", "namespaces", "matchLabels", nsLabel)
		byPod, _, _ := unstructured.NestedString(o.Object, "spec", "subject", "pods", "namespaceSelector", "matchLabels", nsLabel)
		if byNS != s.Namespace() && byPod != s.Namespace() {
			return fmt.Errorf("fixture ClusterNetworkPolicy %s: spec.subject must pin %s to %s", o.GetName(), nsLabel, s.Namespace())
		}
	}
	return nil
}
