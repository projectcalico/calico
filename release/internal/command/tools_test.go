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

package command

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGit(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(GitRunner) error
		want Call
	}{
		{
			name: "version runs in the bound dir",
			run: func(g GitRunner) error {
				_, err := g.In("/repo").Version(true)
				return err
			},
			want: Call{Name: "git", Args: []string{"describe", "--tags", "--always", "--long", "--abbrev=12", "--dirty"}, Dir: "/repo"},
		},
		{
			name: "branch runs in the bound dir",
			run: func(g GitRunner) error {
				_, err := g.In("/repo").Branch()
				return err
			},
			want: Call{Name: "git", Args: []string{"rev-parse", "--abbrev-ref", "HEAD"}, Dir: "/repo"},
		},
		{
			name: "dirty describes with --dirty in the bound dir",
			run: func(g GitRunner) error {
				_, err := g.In("/repo").Dirty()
				return err
			},
			want: Call{Name: "git", Args: []string{"describe", "--tags", "--always", "--long", "--abbrev=12", "--dirty"}, Dir: "/repo"},
		},
		{
			name: "repo root runs where the caller is",
			run: func(g GitRunner) error {
				_, err := g.RepoRoot()
				return err
			},
			want: Call{Name: "git", Args: []string{"rev-parse", "--show-toplevel"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &Recorder{}
			if err := tc.run(Git(r)); err != nil {
				t.Fatalf("run: %v", err)
			}
			if diff := cmp.Diff([]Call{tc.want}, r.Calls()); diff != "" {
				t.Errorf("calls (-want +got):\n%s", diff)
			}
		})
	}

	for _, tc := range []struct {
		name  string
		check func(GitRunner) (bool, error)
		out   string
		want  bool
	}{
		{name: "dirty sees the -dirty suffix", check: func(g GitRunner) (bool, error) { return g.In("/repo").Dirty() }, out: "v3.30.0-0-gabc-dirty", want: true},
		{name: "dirty on a clean tree", check: func(g GitRunner) (bool, error) { return g.In("/repo").Dirty() }, out: "v3.30.0-0-gabc"},
		{name: "porcelain sees any status line", check: func(g GitRunner) (bool, error) { return g.In("/repo").Porcelain() }, out: "?? new.txt", want: true},
		{name: "porcelain on a clean tree", check: func(g GitRunner) (bool, error) { return g.In("/repo").Porcelain() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &Recorder{Reply: func(Call) (string, error) { return tc.out, nil }}
			got, err := tc.check(Git(r))
			if err != nil {
				t.Fatalf("check: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
	t.Run("resolve returns the commit a ref names", func(t *testing.T) {
		r := &Recorder{Reply: func(Call) (string, error) { return "abc123", nil }}
		got, ok := Git(r).In("/repo").Resolve("refs/tags/v1")
		if !ok || got != "abc123" {
			t.Errorf("got (%q, %v), want (abc123, true)", got, ok)
		}
		want := []Call{{Name: "git", Args: []string{"rev-parse", "--verify", "--quiet", "refs/tags/v1"}, Dir: "/repo"}}
		if diff := cmp.Diff(want, r.Calls()); diff != "" {
			t.Errorf("calls (-want +got):\n%s", diff)
		}
	})
	t.Run("resolve reports a missing ref as not found", func(t *testing.T) {
		r := &Recorder{Reply: func(Call) (string, error) { return "", errors.New("exit status 1") }}
		if _, ok := Git(r).Resolve("refs/tags/v1"); ok {
			t.Error("ok = true, want false")
		}
	})
	t.Run("is-ancestor reads git's exit status", func(t *testing.T) {
		yes := &Recorder{}
		no := &Recorder{Reply: func(Call) (string, error) { return "", errors.New("exit status 1") }}
		if !Git(yes).IsAncestor("a", "b") {
			t.Error("exit 0: got false, want true")
		}
		if Git(no).IsAncestor("a", "b") {
			t.Error("exit 1: got true, want false")
		}
	})
}

func TestMake(t *testing.T) {
	t.Run("runs each target in its dir", func(t *testing.T) {
		r := &Recorder{}
		if _, err := Make(r, "/repo").Run("build push", WithEnv("A=1")); err != nil {
			t.Fatalf("run: %v", err)
		}
		want := []Call{{Name: "make", Args: []string{"build", "push"}, Dir: "/repo", Env: []string{"A=1"}}}
		if diff := cmp.Diff(want, r.Calls()); diff != "" {
			t.Errorf("calls (-want +got):\n%s", diff)
		}
	})
	t.Run("print silences make's own output", func(t *testing.T) {
		r := &Recorder{}
		if _, err := Make(r, "/repo").Print("build-images"); err != nil {
			t.Fatalf("print: %v", err)
		}
		want := []Call{{Name: "make", Args: []string{"-s", "--no-print-directory", "build-images"}, Dir: "/repo"}}
		if diff := cmp.Diff(want, r.Calls()); diff != "" {
			t.Errorf("calls (-want +got):\n%s", diff)
		}
	})
	t.Run("its dir wins over a dir option", func(t *testing.T) {
		r := &Recorder{}
		if _, err := Make(r, "/repo").Run("build", WithDir("/elsewhere")); err != nil {
			t.Fatalf("run: %v", err)
		}
		if got := r.Calls()[0].Dir; got != "/repo" {
			t.Errorf("dir = %q, want /repo", got)
		}
	})
}
