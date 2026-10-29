// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package plan

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func noop() error { return nil }

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		opts    Options
		nodes   []Node
		wantErr string
	}{
		{
			name:  "a requirement earlier in the list is met",
			nodes: []Node{{Name: "a", Do: noop}, {Name: "b", Requires: []string{"a"}, Do: noop}},
		},
		{
			name:    "a requirement not in the run fails",
			nodes:   []Node{{Name: "b", Requires: []string{"a"}, Do: noop}},
			wantErr: `node "b" requires "a", which does not exist`,
		},
		{
			name:    "a requirement turned off fails",
			nodes:   []Node{{Name: "a", When: func() bool { return false }, Do: noop}, {Name: "b", Requires: []string{"a"}, Do: noop}},
			wantErr: `node "b" requires "a", which is off in this run`,
		},
		{
			name:    "a skipped requirement fails",
			opts:    Options{Skip: map[string]bool{"a": true}},
			nodes:   []Node{{Name: "a", Do: noop}, {Name: "b", Requires: []string{"a"}, Do: noop}},
			wantErr: `node "b" requires "a", which is off in this run`,
		},
		{
			name:  "an off node's requirements are not checked",
			nodes: []Node{{Name: "b", When: func() bool { return false }, Requires: []string{"a"}, Do: noop}},
		},
		{
			name:    "a requirement later in the list fails",
			nodes:   []Node{{Name: "b", Requires: []string{"a"}, Do: noop}, {Name: "a", Do: noop}},
			wantErr: `node "b" requires "a", which runs after it`,
		},
		{
			name:    "a duplicate name fails",
			nodes:   []Node{{Name: "a", Do: noop}, {Name: "a", Do: noop}},
			wantErr: `node "a" appears more than once`,
		},
		{
			name:    "a node with no name fails",
			nodes:   []Node{{Do: noop}},
			wantErr: "node 0 has no name",
		},
		{
			name:    "a node with nothing to do fails",
			nodes:   []Node{{Name: "a"}},
			wantErr: `node "a" has nothing to do`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.opts, tt.nodes...)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("New() unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("New() error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestRun(t *testing.T) {
	// node records each call it receives, so a case can assert the order.
	node := func(calls *[]string, name string, fail string) Node {
		call := func(verb string) func() error {
			return func() error {
				*calls = append(*calls, verb+" "+name)
				if verb == fail {
					return errors.New("boom")
				}
				return nil
			}
		}
		return Node{Name: name, Validate: call("validate"), Do: call("do"), Verify: call("verify"), Rollback: call("rollback")}
	}

	tests := []struct {
		name      string
		fail      map[string]string // node name to the verb that fails
		wantCalls []string
		wantErr   bool
	}{
		{
			name: "every node validates before any node runs",
			wantCalls: []string{
				"validate a", "validate b",
				"do a", "verify a", "do b", "verify b",
			},
		},
		{
			name:      "validate failures stop the run before any node runs",
			fail:      map[string]string{"a": "validate", "b": "validate"},
			wantCalls: []string{"validate a", "validate b"},
			wantErr:   true,
		},
		{
			name: "a failed node rolls back the nodes before it",
			fail: map[string]string{"b": "do"},
			wantCalls: []string{
				"validate a", "validate b",
				"do a", "verify a", "do b",
				"rollback a",
			},
			wantErr: true,
		},
		{
			name: "a failed verify rolls back its own node too, newest first",
			fail: map[string]string{"b": "verify"},
			wantCalls: []string{
				"validate a", "validate b",
				"do a", "verify a", "do b", "verify b",
				"rollback b", "rollback a",
			},
			wantErr: true,
		},
		{
			name: "a failed rollback is reported and the rest still roll back",
			fail: map[string]string{"a": "rollback", "b": "rollback", "c": "do"},
			wantCalls: []string{
				"validate a", "validate b", "validate c",
				"do a", "verify a", "do b", "verify b", "do c",
				"rollback b", "rollback a",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls []string
			names := []string{"a", "b"}
			if _, ok := tt.fail["c"]; ok {
				names = append(names, "c")
			}
			var nodes []Node
			for _, n := range names {
				nodes = append(nodes, node(&calls, n, tt.fail[n]))
			}
			p, err := New(Options{}, nodes...)
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			err = p.Run()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Run() error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.wantCalls, calls); diff != "" {
				t.Errorf("calls (-want +got):\n%s", diff)
			}
		})
	}

	t.Run("off and skipped nodes neither validate nor run", func(t *testing.T) {
		var calls []string
		off := node(&calls, "off", "")
		off.When = func() bool { return false }
		p, err := New(Options{Skip: map[string]bool{"skipped": true}}, node(&calls, "a", ""), off, node(&calls, "skipped", ""))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if err := p.Run(); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if diff := cmp.Diff([]string{"validate a", "do a", "verify a"}, calls); diff != "" {
			t.Errorf("calls (-want +got):\n%s", diff)
		}
	})

	t.Run("a plan-only run validates, and runs nothing even when validation fails", func(t *testing.T) {
		var calls []string
		p, err := New(Options{Preview: true}, node(&calls, "a", "validate"), node(&calls, "b", ""))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if err := p.Run(); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if diff := cmp.Diff([]string{"validate a", "validate b"}, calls); diff != "" {
			t.Errorf("calls (-want +got):\n%s", diff)
		}
	})

	t.Run("a node without optional verbs runs and is skipped on rollback", func(t *testing.T) {
		p, err := New(Options{}, Node{Name: "a", Do: noop}, Node{Name: "b", Do: func() error { return errors.New("boom") }})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if err := p.Run(); err == nil || !strings.Contains(err.Error(), "b: boom") {
			t.Fatalf("Run() error = %v, want b: boom", err)
		}
	})
	t.Run("a panicking node rolls back the nodes before it and still panics", func(t *testing.T) {
		var calls []string
		p, err := New(Options{}, node(&calls, "a", ""), Node{Name: "b", Do: func() error { panic("boom") }})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		func() {
			defer func() {
				if r := recover(); r != "boom" {
					t.Errorf("recovered %v, want boom", r)
				}
			}()
			_ = p.Run()
		}()
		want := []string{"validate a", "do a", "verify a", "rollback a"}
		if diff := cmp.Diff(want, calls); diff != "" {
			t.Errorf("calls (-want +got):\n%s", diff)
		}
	})
}

func TestReplace(t *testing.T) {
	nodes := []Node{{Name: "a", Do: noop}, {Name: "b", Do: noop}}

	t.Run("swaps the named node in place", func(t *testing.T) {
		got, err := Replace(nodes, Node{Name: "a", Requires: []string{"x"}, Do: noop})
		if err != nil {
			t.Fatalf("Replace: %v", err)
		}
		if diff := cmp.Diff([]string{"a", "b"}, names(got)); diff != "" {
			t.Errorf("names (-want +got):\n%s", diff)
		}
		if diff := cmp.Diff([]string{"x"}, got[0].Requires); diff != "" {
			t.Errorf("replaced node's requires (-want +got):\n%s", diff)
		}
		if nodes[0].Requires != nil {
			t.Error("Replace modified its input")
		}
	})

	t.Run("an absent name fails", func(t *testing.T) {
		if _, err := Replace(nodes, Node{Name: "c", Do: noop}); err == nil {
			t.Fatal("Replace() = nil, want error")
		}
	})
}

func TestRemove(t *testing.T) {
	nodes := []Node{{Name: "a", Do: noop}, {Name: "b", Do: noop}}

	t.Run("drops the named node", func(t *testing.T) {
		got, err := Remove(nodes, "a")
		if err != nil {
			t.Fatalf("Remove: %v", err)
		}
		if diff := cmp.Diff([]string{"b"}, names(got)); diff != "" {
			t.Errorf("names (-want +got):\n%s", diff)
		}
		if diff := cmp.Diff([]string{"a", "b"}, names(nodes)); diff != "" {
			t.Errorf("Remove modified its input (-want +got):\n%s", diff)
		}
	})

	t.Run("an absent name fails", func(t *testing.T) {
		if _, err := Remove(nodes, "c"); err == nil {
			t.Fatal("Remove() = nil, want error")
		}
	})
}

func names(nodes []Node) []string {
	var out []string
	for _, n := range nodes {
		out = append(out, n.Name)
	}
	return out
}
