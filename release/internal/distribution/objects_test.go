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
	"errors"
	"hash/crc32"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

type fakeObject struct {
	body    string
	modTime time.Time
}

// fakeStore is a bucket in memory that records what each transfer did.
type fakeStore struct {
	mu      sync.Mutex
	objects map[string]fakeObject
	puts    []string
	removes []string
	err     error
}

func newFakeStore(objects map[string]fakeObject) *fakeStore {
	if objects == nil {
		objects = map[string]fakeObject{}
	}
	return &fakeStore{objects: objects}
}

func (f *fakeStore) list(_ context.Context, prefix string) (map[string]object, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	out := map[string]object{}
	for key, obj := range f.objects {
		if strings.HasPrefix(key, prefix) {
			out[key] = object{
				size:    int64(len(obj.body)),
				modTime: obj.modTime,
				crc32c:  crc32.Checksum([]byte(obj.body), crc32.MakeTable(crc32.Castagnoli)),
			}
		}
	}
	return out, nil
}

func (f *fakeStore) put(_ context.Context, key, src string) error {
	bs, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.objects[key] = fakeObject{body: string(bs), modTime: time.Now()}
	f.puts = append(f.puts, key)
	return nil
}

func (f *fakeStore) get(_ context.Context, key, dest string) error {
	f.mu.Lock()
	obj, ok := f.objects[key]
	f.mu.Unlock()
	if !ok {
		return errors.New("no such object")
	}
	return os.WriteFile(dest, []byte(obj.body), 0o644)
}

func (f *fakeStore) remove(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.objects, key)
	f.removes = append(f.removes, key)
	return nil
}

func (f *fakeStore) sortedPuts() []string {
	return slices.Sorted(slices.Values(f.puts))
}

// writeTree writes files under a new directory, each body its own name, and
// dates every file at stamp.
func writeTree(t *testing.T, stamp time.Time, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range names {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestTransferUpload(t *testing.T) {
	ctx := context.Background()
	past := time.Now().Add(-time.Hour)

	t.Run("a file sent to a prefix keeps its name", func(t *testing.T) {
		store := newFakeStore(nil)
		src := filepath.Join(writeTree(t, past, "release.tgz"), "release.tgz")
		if err := (transfer{store: store}).upload(ctx, src, "archives/"); err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff([]string{"archives/release.tgz"}, store.puts); diff != "" {
			t.Errorf("puts (-want +got):\n%s", diff)
		}
	})

	t.Run("a file sent to a key takes that key", func(t *testing.T) {
		store := newFakeStore(nil)
		src := filepath.Join(writeTree(t, past, "local.zip"), "local.zip")
		if err := (transfer{store: store}).upload(ctx, src, "dev/windows-abc.zip"); err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff([]string{"dev/windows-abc.zip"}, store.puts); diff != "" {
			t.Errorf("puts (-want +got):\n%s", diff)
		}
	})

	// Without the slash a tree would land beside the prefix, under charts-x/.
	t.Run("a tree goes under the key as a prefix", func(t *testing.T) {
		store := newFakeStore(nil)
		src := writeTree(t, past, "index.yaml", "sub/a.tgz")
		if err := (transfer{store: store}).upload(ctx, src, "charts"); err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff([]string{"charts/index.yaml", "charts/sub/a.tgz"}, store.sortedPuts()); diff != "" {
			t.Errorf("puts (-want +got):\n%s", diff)
		}
	})

	t.Run("a copy rewrites what is already there", func(t *testing.T) {
		store := newFakeStore(map[string]fakeObject{"x/a": {body: "a", modTime: time.Now()}})
		if err := (transfer{store: store}).upload(ctx, writeTree(t, past, "a"), "x/"); err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff([]string{"x/a"}, store.puts); diff != "" {
			t.Errorf("puts (-want +got):\n%s", diff)
		}
	})

	t.Run("an aws sync sends only new, resized or newer files and deletes nothing", func(t *testing.T) {
		later := time.Now()
		store := newFakeStore(map[string]fakeObject{
			"x/same":    {body: "same", modTime: later},
			"x/resized": {body: "old", modTime: later},
			"x/newer":   {body: "newer", modTime: past.Add(-time.Hour)},
			"x/extra":   {body: "extra", modTime: later},
		})
		src := writeTree(t, past, "same", "resized", "newer", "new")
		if err := (transfer{store: store, sync: true, differs: newerOrResized}).upload(ctx, src, "x/"); err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff([]string{"x/new", "x/newer", "x/resized"}, store.sortedPuts()); diff != "" {
			t.Errorf("puts (-want +got):\n%s", diff)
		}
		if len(store.removes) != 0 {
			t.Errorf("removed %v, want nothing", store.removes)
		}
	})

	t.Run("a mirror sends changed content and deletes what the source dropped", func(t *testing.T) {
		store := newFakeStore(map[string]fakeObject{
			"h/same":    {body: "same", modTime: past},
			"h/changed": {body: "CHANGED", modTime: past},
			"h/dropped": {body: "dropped", modTime: past},
			// Only under h/ counts: a sibling with a longer name is not part of it.
			"h-other/x": {body: "x", modTime: past},
		})
		src := writeTree(t, time.Now(), "same", "changed")
		if err := (transfer{store: store, sync: true, mirror: true, differs: contentDiffers}).upload(ctx, src, "h"); err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff([]string{"h/changed"}, store.puts); diff != "" {
			t.Errorf("puts (-want +got):\n%s", diff)
		}
		if diff := cmp.Diff([]string{"h/dropped"}, store.removes); diff != "" {
			t.Errorf("removes (-want +got):\n%s", diff)
		}
	})

	t.Run("filters leave excluded files unsent and undeleted", func(t *testing.T) {
		store := newFakeStore(map[string]fakeObject{"r/dists/old": {body: "old", modTime: past}})
		rules, err := filterRules([]string{"dists/*"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		src := writeTree(t, past, "pool/a.deb", "dists/stable/Release")
		tr := transfer{store: store, sync: true, mirror: true, rules: rules, differs: contentDiffers}
		if err := tr.upload(ctx, src, "r/"); err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff([]string{"r/pool/a.deb"}, store.puts); diff != "" {
			t.Errorf("puts (-want +got):\n%s", diff)
		}
		if len(store.removes) != 0 {
			t.Errorf("removed %v, want the excluded object kept", store.removes)
		}
	})

	t.Run("a dry run changes nothing", func(t *testing.T) {
		store := newFakeStore(map[string]fakeObject{"h/dropped": {body: "dropped", modTime: past}})
		src := writeTree(t, past, "new")
		tr := transfer{store: store, sync: true, mirror: true, dryRun: true, differs: contentDiffers}
		if err := tr.upload(ctx, src, "h/"); err != nil {
			t.Fatal(err)
		}
		if len(store.puts) != 0 || len(store.removes) != 0 {
			t.Errorf("puts %v, removes %v, want neither", store.puts, store.removes)
		}
	})

	t.Run("a failure names the object", func(t *testing.T) {
		store := newFakeStore(nil)
		store.err = errors.New("denied")
		src := filepath.Join(writeTree(t, past, "a.tgz"), "a.tgz")
		err := (transfer{store: store}).upload(ctx, src, "archives/")
		if err == nil || !strings.Contains(err.Error(), "archives/a.tgz") {
			t.Errorf("error = %v, want it to name archives/a.tgz", err)
		}
	})
}

func TestTransferFetch(t *testing.T) {
	ctx := context.Background()
	stamp := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

	t.Run("a tree lands under dest with the objects' times", func(t *testing.T) {
		store := newFakeStore(map[string]fakeObject{
			"rpms/v1/repodata/repomd.xml": {body: "xml", modTime: stamp},
			"rpms/v1/a.rpm":               {body: "rpm", modTime: stamp},
			"rpms/v1/":                    {body: "", modTime: stamp},
		})
		dest := t.TempDir()
		if err := (transfer{store: store}).fetch(ctx, "rpms/v1/", dest); err != nil {
			t.Fatal(err)
		}
		got, err := localTree(dest)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff([]string{"a.rpm", "repodata/repomd.xml"}, slices.Sorted(maps.Keys(got))); diff != "" {
			t.Errorf("files (-want +got):\n%s", diff)
		}
		if !got["a.rpm"].modTime.Equal(stamp) {
			t.Errorf("a.rpm dated %v, want %v", got["a.rpm"].modTime, stamp)
		}
	})

	t.Run("a sync leaves a current file alone", func(t *testing.T) {
		store := newFakeStore(map[string]fakeObject{
			"db/current": {body: "current", modTime: stamp},
			"db/updated": {body: "updated", modTime: stamp.Add(time.Hour)},
		})
		dest := writeTree(t, stamp, "current", "updated")
		if err := os.WriteFile(filepath.Join(dest, "current"), []byte("current"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(filepath.Join(dest, "current"), stamp, stamp); err != nil {
			t.Fatal(err)
		}
		before, err := os.Stat(filepath.Join(dest, "current"))
		if err != nil {
			t.Fatal(err)
		}
		if err := (transfer{store: store, sync: true}).fetch(ctx, "db/", dest); err != nil {
			t.Fatal(err)
		}
		after, err := localTree(dest)
		if err != nil {
			t.Fatal(err)
		}
		if !after["current"].modTime.Equal(before.ModTime()) {
			t.Error("current was rewritten")
		}
		if !after["updated"].modTime.Equal(stamp.Add(time.Hour)) {
			t.Errorf("updated dated %v, want the object's newer time", after["updated"].modTime)
		}
	})

	t.Run("a key that climbs out of dest is refused", func(t *testing.T) {
		store := newFakeStore(map[string]fakeObject{"rpms/v1/../../escaped": {body: "x", modTime: stamp}})
		root := t.TempDir()
		dest := filepath.Join(root, "a", "b")
		err := (transfer{store: store}).fetch(ctx, "rpms/v1/", dest)
		if err == nil || !strings.Contains(err.Error(), "outside") {
			t.Errorf("got %v, want an error naming the escape", err)
		}
		if _, err := os.Stat(filepath.Join(root, "escaped")); !os.IsNotExist(err) {
			t.Errorf("escaped file exists: %v", err)
		}
	})

	t.Run("a key without a slash is one object", func(t *testing.T) {
		store := newFakeStore(map[string]fakeObject{"windows-v1.zip": {body: "zip", modTime: stamp}})
		dest := filepath.Join(t.TempDir(), "w.zip")
		if err := (transfer{store: store}).fetch(ctx, "windows-v1.zip", dest); err != nil {
			t.Fatal(err)
		}
		if bs, err := os.ReadFile(dest); err != nil || string(bs) != "zip" {
			t.Errorf("read %q, %v; want zip", bs, err)
		}
	})
}

func TestBucketURI(t *testing.T) {
	for _, tc := range []struct {
		name, uri, scheme   string
		wantBucket, wantKey string
		wantErr             bool
	}{
		{name: "a prefix", uri: "s3://bucket/charts/", scheme: "s3", wantBucket: "bucket", wantKey: "charts/"},
		{name: "a bucket root", uri: "gs://bucket", scheme: "gs", wantBucket: "bucket"},
		{name: "the wrong scheme", uri: "gs://bucket/x", scheme: "s3", wantErr: true},
		{name: "no bucket", uri: "s3:///x", scheme: "s3", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bucket, key, err := bucketURI(tc.uri, tc.scheme)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, want error %v", err, tc.wantErr)
			}
			if bucket != tc.wantBucket || key != tc.wantKey {
				t.Errorf("got %q %q, want %q %q", bucket, key, tc.wantBucket, tc.wantKey)
			}
		})
	}
}

func TestContentDiffers(t *testing.T) {
	src := filepath.Join(writeTree(t, time.Now(), "abc"), "abc")
	sum := crc32.Checksum([]byte("abc"), crc32.MakeTable(crc32.Castagnoli))
	for _, tc := range []struct {
		name string
		dst  object
		want bool
	}{
		{name: "same size and checksum", dst: object{size: 3, crc32c: sum}, want: false},
		{name: "same size, other content", dst: object{size: 3, crc32c: sum + 1}, want: true},
		{name: "other size", dst: object{size: 4, crc32c: sum}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := contentDiffers(object{size: 3}, tc.dst, src)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("differs = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTransferIncluded(t *testing.T) {
	for _, tc := range []struct {
		name             string
		exclude, include []string
		rel              string
		want             bool
	}{
		{name: "no rules", rel: "a/b", want: true},
		{name: "an exclude", exclude: []string{"dists/*"}, rel: "dists/stable/Release", want: false},
		{name: "a later include wins", exclude: []string{"*"}, include: []string{"dists/*"}, rel: "dists/stable/Release", want: true},
		{name: "an include does not let in what it does not match", exclude: []string{"*"}, include: []string{"dists/*"}, rel: "pool/a.deb", want: false},
		{name: "a leading */ matches at any depth", exclude: []string{"*/README.md"}, rel: "ocp/sub/README.md", want: false},
		{name: "a bare name matches only the top level", exclude: []string{"README.md"}, rel: "ocp/README.md", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules, err := filterRules(tc.exclude, tc.include)
			if err != nil {
				t.Fatal(err)
			}
			if got := (transfer{rules: rules}).included(tc.rel); got != tc.want {
				t.Errorf("included(%q) = %v, want %v", tc.rel, got, tc.want)
			}
		})
	}
}

func TestFnmatch(t *testing.T) {
	for _, tc := range []struct {
		pattern, name string
		want          bool
	}{
		{"*", "a/b/c", true},
		{"*/repodata/repomd.xml", "el9/repodata/repomd.xml", true},
		{"*/repodata/repomd.xml", "repodata/repomd.xml", false},
		{"a?c", "a/c", true},
		{"[ab].txt", "b.txt", true},
		{"[!ab].txt", "a.txt", false},
		{"[]].txt", "].txt", true},
		{"[", "[", true},
		{"a.b", "aXb", false},
		{"*.YAML", "x.yaml", false},
	} {
		t.Run(tc.pattern+" "+tc.name, func(t *testing.T) {
			re, err := fnmatch(tc.pattern)
			if err != nil {
				t.Fatal(err)
			}
			if got := re.MatchString(tc.name); got != tc.want {
				t.Errorf("match = %v, want %v (regexp %s)", got, tc.want, re)
			}
		})
	}
}

// The want values are what downloads.tigera.io served when the aws CLI uploaded.
func TestContentType(t *testing.T) {
	for name, want := range map[string]string{
		"tigera-operator.yaml":        "application/yaml",
		"ocp.tgz":                     "application/x-tar",
		"release-v1.tar.gz":           "application/x-tar",
		"calicoctl-windows.exe":       "application/x-msdos-program",
		"calicoctl-darwin-amd64":      "",
		"repodata/primary.xml.gz":     "application/xml",
		"a.gz":                        "",
		"metadata.yaml.sigstore.json": "application/json",
		"INDEX.HTML":                  "text/html",
		"SHA256SUMS":                  "",
	} {
		t.Run(name, func(t *testing.T) {
			if got := contentType(name); got != want {
				t.Errorf("contentType = %q, want %q", got, want)
			}
		})
	}
}
