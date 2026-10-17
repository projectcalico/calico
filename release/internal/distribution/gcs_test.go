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

package distribution

import (
	"context"
	"crypto/md5"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// memStore is an in-memory objectStore. err, when set, fails every call.
type memStore struct {
	mu      sync.Mutex
	err     error
	objects map[string]remoteObject // "bucket/name"
	types   map[string]string
	uploads []string
	deletes []string
}

func (m *memStore) List(_ context.Context, bucket, prefix string) (map[string]remoteObject, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return nil, m.err
	}
	out := map[string]remoteObject{}
	for key, o := range m.objects {
		name, ok := strings.CutPrefix(key, bucket+"/")
		if ok && strings.HasPrefix(name, prefix) {
			out[name] = o
		}
	}
	return out, nil
}

func (m *memStore) Upload(_ context.Context, bucket string, o localObject) error {
	data, err := os.ReadFile(o.path)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.put(bucket+"/"+o.name, data)
	m.types[o.name] = contentType(o.name, data)
	m.uploads = append(m.uploads, o.name)
	return nil
}

func (m *memStore) Delete(_ context.Context, bucket, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	delete(m.objects, bucket+"/"+name)
	m.deletes = append(m.deletes, name)
	return nil
}

func (m *memStore) put(key string, data []byte) {
	if m.objects == nil {
		m.objects = map[string]remoteObject{}
		m.types = map[string]string{}
	}
	sum := md5.Sum(data)
	m.objects[key] = remoteObject{size: int64(len(data)), md5: sum[:]}
}

func (m *memStore) names() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for k := range m.objects {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// A hashrelease is republished with Sync, so what the new build dropped must go,
// and nothing outside its own folder may, however alike the names.
func TestGCSSyncDeletesOnlyWhatTheSourceDroppedUnderItsPrefix(t *testing.T) {
	src := writeTree(t, map[string]string{"index.html": "new", "keep.yaml": "same"})
	m := &memStore{}
	m.put("b/hash/old.yaml", []byte("stale"))
	m.put("b/hash/keep.yaml", []byte("same"))
	m.put("b/hash-old/index.html", []byte("another hashrelease"))
	m.put("b/all-releases", []byte("library"))

	if err := (GCS{URI: "gs://b/hash", Sync: true, store: m}).Publish(context.Background(), src); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	want := []string{"b/all-releases", "b/hash-old/index.html", "b/hash/index.html", "b/hash/keep.yaml"}
	if diff := cmp.Diff(want, m.names()); diff != "" {
		t.Errorf("objects (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"hash/index.html"}, m.uploads); diff != "" {
		t.Errorf("uploads (-want +got), an unchanged file must not be sent again:\n%s", diff)
	}
}

func TestGCSWithoutSyncLeavesExtraObjects(t *testing.T) {
	src := writeTree(t, map[string]string{"a.txt": "a"})
	m := &memStore{}
	m.put("b/x/extra.txt", []byte("extra"))
	if err := (GCS{URI: "gs://b/x", store: m}).Publish(context.Background(), src); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if diff := cmp.Diff([]string{"b/x/a.txt", "b/x/extra.txt"}, m.names()); diff != "" {
		t.Errorf("objects (-want +got):\n%s", diff)
	}
}

func TestGCSObjectNames(t *testing.T) {
	for _, tc := range []struct {
		name string
		uri  string
		dir  bool
		want []string
	}{
		{name: "a file to an object", uri: "gs://b/archives/calico.tgz", want: []string{"b/archives/calico.tgz"}},
		{name: "a file into a folder", uri: "gs://b/archives/", want: []string{"b/archives/artifact.tgz"}},
		{name: "a tree under a prefix", uri: "gs://b/hash", dir: true, want: []string{"b/hash/manifests/calico.yaml"}},
		{name: "a tree under a prefix with a slash", uri: "gs://b/hash/", dir: true, want: []string{"b/hash/manifests/calico.yaml"}},
		{name: "a tree at the bucket root", uri: "gs://b", dir: true, want: []string{"b/manifests/calico.yaml"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := srcPath(t, false)
			if tc.dir {
				src = writeTree(t, map[string]string{"manifests/calico.yaml": "x"})
			}
			m := &memStore{}
			if err := (GCS{URI: tc.uri, store: m}).Publish(context.Background(), src); err != nil {
				t.Fatalf("Publish: %v", err)
			}
			if diff := cmp.Diff(tc.want, m.names()); diff != "" {
				t.Errorf("objects (-want +got):\n%s", diff)
			}
		})
	}
}

// A file owns only its own object: a sync must not take objects that merely
// start with its name.
func TestGCSSyncOfAFileKeepsItsNeighbours(t *testing.T) {
	m := &memStore{}
	m.put("b/calico.tgz.sha256", []byte("sum"))
	if err := (GCS{URI: "gs://b/calico.tgz", Sync: true, store: m}).Publish(context.Background(), srcPath(t, false)); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if diff := cmp.Diff([]string{"b/calico.tgz", "b/calico.tgz.sha256"}, m.names()); diff != "" {
		t.Errorf("objects (-want +got):\n%s", diff)
	}
}

func TestGCSDryRunWritesNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		sync bool
		dir  bool
	}{
		{name: "a file"},
		{name: "a tree", dir: true},
		{name: "a synced tree", sync: true, dir: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := srcPath(t, false)
			if tc.dir {
				src = writeTree(t, map[string]string{"new.txt": "x"})
			}
			m := &memStore{}
			m.put("b/x/stale.txt", []byte("stale"))
			if err := (GCS{URI: "gs://b/x", Sync: tc.sync, DryRun: true, store: m}).Publish(context.Background(), src); err != nil {
				t.Fatalf("Publish: %v", err)
			}
			if len(m.uploads) != 0 || len(m.deletes) != 0 {
				t.Errorf("uploads %v, deletes %v, want a dry run to change nothing", m.uploads, m.deletes)
			}
		})
	}
}

// The hashrelease bucket is a website: a browser refuses a stylesheet or a
// script served as text/plain.
func TestGCSContentTypeFollowsTheExtension(t *testing.T) {
	src := writeTree(t, map[string]string{"index.html": "<p>x</p>", "site.css": "p{}", "app.js": "x()", "notes": "plain words"})
	m := &memStore{}
	if err := (GCS{URI: "gs://b/h", store: m}).Publish(context.Background(), src); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	for name, want := range map[string]string{
		"h/index.html": "text/html",
		"h/site.css":   "text/css",
		"h/app.js":     "text/javascript",
		"h/notes":      "text/plain",
	} {
		if got := m.types[name]; !strings.HasPrefix(got, want) {
			t.Errorf("%s: content type %q, want %s", name, got, want)
		}
	}
}

func TestGCSRejectsAURIThatIsNotGS(t *testing.T) {
	for _, uri := range []string{"s3://b/x", "gs:///x", "/local/path"} {
		if err := (GCS{URI: uri, store: &memStore{}}).Publish(context.Background(), srcPath(t, true)); err == nil {
			t.Errorf("%s: expected an error", uri)
		}
	}
}
