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

package aptrepo

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

type call struct {
	name string
	args []string
}

// fakeRunner answers dpkg-deb with a version per file and gpg with a fixed key.
type fakeRunner struct {
	versions map[string]string
	key      string
	calls    []call
}

func (f *fakeRunner) Run(name string, args, _ []string) (string, error) {
	f.calls = append(f.calls, call{name: name, args: args})
	switch name {
	case "dpkg-deb":
		v, ok := f.versions[filepath.Base(args[len(args)-1])]
		if !ok {
			return "", fmt.Errorf("no version for %s", args[len(args)-1])
		}
		return v, nil
	case "gpg":
		return f.key, nil
	}
	return "", nil
}

func (f *fakeRunner) RunNoCapture(name string, args, env []string) error {
	_, err := f.Run(name, args, env)
	return err
}

func (f *fakeRunner) RunInDir(_, name string, args, env []string) (string, error) {
	return f.Run(name, args, env)
}

func (f *fakeRunner) RunInDirNoCapture(_, name string, args, env []string) error {
	_, err := f.Run(name, args, env)
	return err
}

func (f *fakeRunner) RunInDirToFile(_, name string, args, env []string, _ string) (string, error) {
	return f.Run(name, args, env)
}

func (f *fakeRunner) named(name string) [][]string {
	var out [][]string
	for _, c := range f.calls {
		if c.name == name {
			out = append(out, c.args)
		}
	}
	return out
}

func newTestRepo(t *testing.T, r *fakeRunner) *Repo {
	t.Helper()
	tmp := t.TempDir()
	repo, err := NewRepo(tmp, filepath.Join(tmp, "out"), RepoConfig{
		ProductName:   "Product v1.2",
		Architectures: []string{"amd64"},
		Components:    []string{"noble", "bookworm"},
		GPGKeyID:      "KEYID",
	}, "https://example.com/debs/v1.2", r)
	if err != nil {
		t.Fatalf("NewRepo: %v", err)
	}
	return repo
}

func writeDebs(t *testing.T, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestRecursiveAddDebsFromDirectories(t *testing.T) {
	t.Run("includes each package in the suite after its version's tilde", func(t *testing.T) {
		r := &fakeRunner{versions: map[string]string{
			"a.deb":  "1.2.0~noble",
			"b.ddeb": "1.2.0-1~bookworm",
		}}
		repo := newTestRepo(t, r)
		dir := writeDebs(t, "a.deb", "b.ddeb", "notes.txt")

		if err := repo.RecursiveAddDebsFromDirectories([]string{dir}); err != nil {
			t.Fatalf("RecursiveAddDebsFromDirectories: %v", err)
		}

		base := []string{"--basedir", repo.BaseDirectory, "--outdir", repo.OutputDirectory, "--ignore=extension"}
		want := [][]string{
			append(slices.Clone(base), "includedeb", "bookworm", filepath.Join(dir, "b.ddeb")),
			append(slices.Clone(base), "includedeb", "noble", filepath.Join(dir, "a.deb")),
		}
		got := r.named("reprepro")
		slices.SortFunc(got, func(a, b []string) int { return strings.Compare(strings.Join(a, " "), strings.Join(b, " ")) })
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("reprepro calls (-want +got):\n%s", diff)
		}
		if n := len(r.named("dpkg-deb")); n != 2 {
			t.Errorf("dpkg-deb ran %d times, want 2", n)
		}
	})

	t.Run("a suite the repo does not configure fails", func(t *testing.T) {
		r := &fakeRunner{versions: map[string]string{"a.deb": "1.2.0~jammy"}}
		repo := newTestRepo(t, r)

		err := repo.RecursiveAddDebsFromDirectories([]string{writeDebs(t, "a.deb")})
		if err == nil || !strings.Contains(err.Error(), "jammy") {
			t.Errorf("want an error naming jammy, got %v", err)
		}
		if calls := r.named("reprepro"); len(calls) != 0 {
			t.Errorf("reprepro ran: %v", calls)
		}
	})

	t.Run("a version without a tilde fails", func(t *testing.T) {
		r := &fakeRunner{versions: map[string]string{"a.deb": "1.2.0"}}
		repo := newTestRepo(t, r)

		err := repo.RecursiveAddDebsFromDirectories([]string{writeDebs(t, "a.deb")})
		if err == nil || !strings.Contains(err.Error(), "tilde") {
			t.Errorf("want a tilde error, got %v", err)
		}
	})
}

func TestWriteSourcesFile(t *testing.T) {
	t.Run("embeds the key read through the runner", func(t *testing.T) {
		r := &fakeRunner{key: "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nabc\n-----END PGP PUBLIC KEY BLOCK-----\n"}
		repo := newTestRepo(t, r)
		if err := os.MkdirAll(repo.OutputDirectory, 0o755); err != nil {
			t.Fatal(err)
		}

		if err := repo.WriteSourcesFile("noble"); err != nil {
			t.Fatalf("WriteSourcesFile: %v", err)
		}

		if diff := cmp.Diff([][]string{{"--armor", "--export", "KEYID"}}, r.named("gpg")); diff != "" {
			t.Errorf("gpg calls (-want +got):\n%s", diff)
		}
		got, err := os.ReadFile(filepath.Join(repo.OutputDirectory, "noble.sources"))
		if err != nil {
			t.Fatal(err)
		}
		want := `X-Repolib-Name: Product v1.2
Types: deb
URIs: https://example.com/debs/v1.2
Suites: noble
Components: main
Architectures: amd64
Signed-By:  -----BEGIN PGP PUBLIC KEY BLOCK-----
 .
 abc
 -----END PGP PUBLIC KEY BLOCK-----
`
		if diff := cmp.Diff(want, string(got)); diff != "" {
			t.Errorf("noble.sources (-want +got):\n%s", diff)
		}
	})

	t.Run("a codename the repo does not configure fails", func(t *testing.T) {
		r := &fakeRunner{}
		if err := newTestRepo(t, r).WriteSourcesFile("jammy"); err == nil {
			t.Error("want an error, got nil")
		}
		if len(r.calls) != 0 {
			t.Errorf("commands ran: %v", r.calls)
		}
	})
}

func TestRepositoryDBExists(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, dbDir string)
		want  bool
	}{
		{name: "no db dir", setup: func(*testing.T, string) {}, want: false},
		{name: "empty db dir", setup: func(t *testing.T, dbDir string) {
			if err := os.MkdirAll(dbDir, 0o755); err != nil {
				t.Fatal(err)
			}
		}, want: false},
		{name: "db with files", setup: func(t *testing.T, dbDir string) {
			if err := os.MkdirAll(dbDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dbDir, "packages.db"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := newTestRepo(t, &fakeRunner{})
			tc.setup(t, filepath.Join(repo.BaseDirectory, "db"))

			got, err := repo.RepositoryDBExists()
			if err != nil {
				t.Fatalf("RepositoryDBExists: %v", err)
			}
			if got != tc.want {
				t.Errorf("RepositoryDBExists() = %v, want %v", got, tc.want)
			}
		})
	}
}
