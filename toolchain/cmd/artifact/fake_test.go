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

package main

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeObject struct {
	data        []byte
	contentType string
	metadata    map[string]string
	created     time.Time
}

type fakeBucket struct {
	mu      sync.Mutex
	objects map[string]*fakeObject
}

func newFakeBucket() *fakeBucket {
	return &fakeBucket{objects: map[string]*fakeObject{}}
}

func (f *fakeBucket) Stat(_ context.Context, name string) (*objectAttrs, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.objects[name]
	if !ok {
		return nil, errNotExist
	}
	return o.attrs(name), nil
}

func (o *fakeObject) attrs(name string) *objectAttrs {
	return &objectAttrs{Name: name, Size: int64(len(o.data)), Created: o.created, Metadata: maps.Clone(o.metadata)}
}

func (f *fakeBucket) List(_ context.Context, prefix, delimiter string) ([]objectAttrs, []string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var objs []objectAttrs
	seen := map[string]bool{}
	var prefixes []string
	for _, name := range slices.Sorted(maps.Keys(f.objects)) {
		rest, ok := strings.CutPrefix(name, prefix)
		if !ok {
			continue
		}
		if delimiter != "" {
			if i := strings.Index(rest, delimiter); i >= 0 {
				p := prefix + rest[:i+len(delimiter)]
				if !seen[p] {
					seen[p] = true
					prefixes = append(prefixes, p)
				}
				continue
			}
		}
		objs = append(objs, *f.objects[name].attrs(name))
	}
	return objs, prefixes, nil
}

func (f *fakeBucket) Read(_ context.Context, name string) (io.ReadCloser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.objects[name]
	if !ok {
		return nil, errNotExist
	}
	return io.NopCloser(bytes.NewReader(o.data)), nil
}

func (f *fakeBucket) Write(_ context.Context, name string, r io.Reader, contentType string, md map[string]string) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	f.put(name, data, contentType, md)
	return nil
}

func (f *fakeBucket) Delete(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.objects[name]; !ok {
		return errNotExist
	}
	delete(f.objects, name)
	return nil
}

func (f *fakeBucket) put(name string, data []byte, contentType string, md map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[name] = &fakeObject{data: data, contentType: contentType, metadata: maps.Clone(md), created: time.Now()}
}

func (f *fakeBucket) get(t *testing.T, name string) *fakeObject {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.objects[name]
	if !ok {
		t.Fatalf("object %q missing; have %v", name, slices.Sorted(maps.Keys(f.objects)))
	}
	return o
}

func (f *fakeBucket) names() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Sorted(maps.Keys(f.objects))
}

// harness runs the CLI in a fresh working directory against fake buckets.
type harness struct {
	t       *testing.T
	env     map[string]string
	buckets map[string]*fakeBucket
	opened  int
	stdout  bytes.Buffer
	stderr  bytes.Buffer
}

func newHarness(t *testing.T) *harness {
	dir := t.TempDir()
	// Tests leave read-only directories behind, which TempDir's cleanup
	// could not remove.
	t.Cleanup(func() { makeWritable(dir) })
	t.Chdir(dir)
	return &harness{
		t: t,
		env: map[string]string{
			"CI_ARTIFACT_STEP_STORAGE": "gs://art/run1/step1",
			"CI_ARTIFACT_STORAGE":      "gs://art/run1/workflow/",
			"CI_CACHE_STORAGE":         "gs://cache/c/",
			"CI_GIT_REPO_NAME":         "calico",
		},
		buckets: map[string]*fakeBucket{},
	}
}

func (h *harness) bucket(name string) *fakeBucket {
	if h.buckets[name] == nil {
		h.buckets[name] = newFakeBucket()
	}
	return h.buckets[name]
}

func (h *harness) run(args ...string) int {
	h.stdout.Reset()
	h.stderr.Reset()
	a := &app{
		getenv: func(k string) string { return h.env[k] },
		stdout: &h.stdout,
		stderr: &lockedWriter{w: &h.stderr},
		open: func(_ context.Context, name string) (bucket, error) {
			h.opened++
			return h.bucket(name), nil
		},
	}
	return a.run(context.Background(), args)
}

// mustRun fails the test unless the command exits with want.
func (h *harness) mustRun(want int, args ...string) {
	h.t.Helper()
	if got := h.run(args...); got != want {
		h.t.Fatalf("artifact %s: exit %d, want %d\nstdout:\n%s\nstderr:\n%s",
			strings.Join(args, " "), got, want, h.stdout.String(), h.stderr.String())
	}
}

func (h *harness) wantStderr(substr string) {
	h.t.Helper()
	if !strings.Contains(h.stderr.String(), substr) {
		h.t.Fatalf("stderr %q does not contain %q", h.stderr.String(), substr)
	}
}

func (h *harness) wantStdout(want string) {
	h.t.Helper()
	if got := h.stdout.String(); got != want {
		h.t.Fatalf("stdout:\n%s\nwant:\n%s", got, want)
	}
}

func writeFile(t *testing.T, name, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func makeWritable(dir string) {
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = os.Chmod(p, 0o755)
		}
		return nil
	})
}
