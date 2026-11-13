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
	"fmt"
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
		got, err := Git(r).In("/repo").Resolve("refs/tags/v1")
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if got != "abc123" {
			t.Errorf("got %q, want abc123", got)
		}
		want := []Call{{Name: "git", Args: []string{"rev-parse", "--verify", "--quiet", "refs/tags/v1"}, Dir: "/repo"}}
		if diff := cmp.Diff(want, r.Calls()); diff != "" {
			t.Errorf("calls (-want +got):\n%s", diff)
		}
	})
	t.Run("resolve tells a missing ref from a git failure", func(t *testing.T) {
		for _, tc := range []struct {
			code     int
			notFound bool
		}{{code: 1, notFound: true}, {code: 128}} {
			r := &Recorder{Reply: func(Call) (string, error) { return "", exitErr(tc.code) }}
			_, err := Git(r).Resolve("refs/tags/v1")
			if err == nil {
				t.Fatalf("exit %d: got nil, want an error", tc.code)
			}
			if got := errors.Is(err, ErrGitRefNotFound); got != tc.notFound {
				t.Errorf("exit %d: errors.Is(err, ErrRefNotFound) = %v, want %v", tc.code, got, tc.notFound)
			}
		}
	})
	t.Run("is-ancestor reads git's exit status", func(t *testing.T) {
		for _, tc := range []struct {
			err     error
			want    bool
			wantErr bool
		}{
			{want: true},
			{err: exitErr(1)},
			{err: exitErr(128), wantErr: true},
		} {
			r := &Recorder{Reply: func(Call) (string, error) { return "", tc.err }}
			got, err := Git(r).IsAncestor("a", "b")
			if (err != nil) != tc.wantErr {
				t.Errorf("reply %v: err = %v, want error %v", tc.err, err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("reply %v: got %v, want %v", tc.err, got, tc.want)
			}
		}
	})
}

func exitErr(code int) error {
	return &Error{Err: fmt.Errorf("exit status %d", code), ExitCode: code}
}

func TestMake(t *testing.T) {
	t.Run("runs each target in its dir", func(t *testing.T) {
		r := &Recorder{}
		if _, err := Make(r, "/repo").Run([]string{"build", "push"}, WithEnv("A=1")); err != nil {
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
	t.Run("print rejects more than one target", func(t *testing.T) {
		r := &Recorder{}
		if _, err := Make(r, "/repo").Print("build-images image-tag-prefix"); err == nil {
			t.Error("print: got nil, want an error")
		}
		if calls := r.Calls(); len(calls) != 0 {
			t.Errorf("calls = %v, want none", calls)
		}
	})
	t.Run("its dir wins over a dir option", func(t *testing.T) {
		r := &Recorder{}
		if _, err := Make(r, "/repo").Run([]string{"build"}, WithDir("/elsewhere")); err != nil {
			t.Fatalf("run: %v", err)
		}
		if got := r.Calls()[0].Dir; got != "/repo" {
			t.Errorf("dir = %q, want /repo", got)
		}
	})
}
