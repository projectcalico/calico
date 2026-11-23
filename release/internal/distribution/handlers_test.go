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
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestDestinationNames(t *testing.T) {
	if got := (S3{URL: parseURL(t, "s3://b/k/")}).Name(); got != "s3://b/k/" {
		t.Errorf("S3 name = %q", got)
	}
	if got := (GCS{URL: parseURL(t, "gs://b/k")}).Name(); got != "gs://b/k" {
		t.Errorf("GCS name = %q", got)
	}
}

func TestS3Handler(t *testing.T) {
	for _, tc := range []struct {
		name   string
		bucket string
		elem   []string
		want   string
	}{
		{"a bare bucket", "bucket", nil, "s3://bucket/"},
		{"a bucket with a key prefix", "bucket/prefix", nil, "s3://bucket/prefix/"},
		{"elements under a key prefix", "bucket/prefix", []string{"v1.0.0", "manifests"}, "s3://bucket/prefix/v1.0.0/manifests/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := S3Handler("prof", tc.bucket, true, tc.elem...).Name(); got != tc.want {
				t.Errorf("URL = %q, want %q", got, tc.want)
			}
		})
	}

	t.Run("sets the profile and dry run", func(t *testing.T) {
		got := S3Handler("prof", "bucket", true)
		if got.Profile != "prof" || !got.DryRun {
			t.Errorf("S3Handler dropped settings: %+v", got)
		}
	})
}

func TestGCSHandler(t *testing.T) {
	got := GCSHandler("bucket/prefix", true, "hash")
	if got.Name() != "gs://bucket/prefix/hash/" || !got.DryRun {
		t.Errorf("GCSHandler = %s, dry run %v; want gs://bucket/prefix/hash/, dry run true", got.Name(), got.DryRun)
	}
}

func TestS3Validate(t *testing.T) {
	src := Upload{Source: "dir"}
	t.Run("accepts an s3 URL", func(t *testing.T) {
		if err := S3Handler("", "bucket", false).Validate(src); err != nil {
			t.Errorf("Validate() = %v, want nil", err)
		}
	})
	t.Run("rejects a gs URL", func(t *testing.T) {
		if err := (S3{URL: parseURL(t, "gs://bucket/x/")}).Validate(src); err == nil {
			t.Error("Validate() = nil, want an error")
		}
	})
}

func TestGCSValidate(t *testing.T) {
	src := Upload{Source: "dir"}
	t.Run("accepts a gs URL", func(t *testing.T) {
		if err := GCSHandler("bucket", false).Validate(src); err != nil {
			t.Errorf("Validate() = %v, want nil", err)
		}
	})
	t.Run("rejects an s3 URL", func(t *testing.T) {
		if err := (GCS{URL: parseURL(t, "s3://bucket/x/")}).Validate(src); err == nil {
			t.Error("Validate() = nil, want an error")
		}
	})
}

func TestS3At(t *testing.T) {
	for _, tc := range []struct {
		name string
		url  string
		elem []string
		want string
	}{
		{"a bare bucket", "s3://bucket", []string{"charts"}, "s3://bucket/charts/"},
		{"a bucket with a trailing slash", "s3://bucket/", []string{"charts"}, "s3://bucket/charts/"},
		{"a bucket with a key prefix", "s3://bucket/prefix", []string{"v1.0.0", "manifests"}, "s3://bucket/prefix/v1.0.0/manifests/"},
		{"no elements", "s3://bucket/prefix", nil, "s3://bucket/prefix/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := (S3{URL: parseURL(t, tc.url)}).At(tc.elem...).Name(); got != tc.want {
				t.Errorf("URL = %q, want %q", got, tc.want)
			}
		})
	}

	t.Run("keeps the other settings", func(t *testing.T) {
		got := S3{URL: parseURL(t, "s3://bucket"), Profile: "prof", DryRun: true}.At("charts")
		if got.Profile != "prof" || !got.DryRun {
			t.Errorf("At dropped settings: %+v", got)
		}
	})
}

func TestS3Publish(t *testing.T) {
	ctx := context.Background()

	t.Run("excludes then includes, as aws did", func(t *testing.T) {
		store := newFakeStore(nil)
		d := S3{URL: parseURL(t, "s3://bucket/debs/"), Exclude: []string{"*"}, Include: []string{"dists/*"}, store: store}
		if err := d.Publish(ctx, writeTree(t, time.Now(), "pool/a.deb", "dists/Release")); err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff([]string{"debs/dists/Release"}, store.puts); diff != "" {
			t.Errorf("puts (-want +got):\n%s", diff)
		}
	})

	t.Run("sync never deletes", func(t *testing.T) {
		store := newFakeStore(map[string]fakeObject{"x/old": {body: "old", modTime: time.Now()}})
		d := S3{URL: parseURL(t, "s3://bucket/x/"), Sync: true, store: store}
		if err := d.Publish(ctx, writeTree(t, time.Now(), "new")); err != nil {
			t.Fatal(err)
		}
		if len(store.removes) != 0 {
			t.Errorf("removed %v", store.removes)
		}
	})

	t.Run("a dry run sends nothing", func(t *testing.T) {
		store := newFakeStore(nil)
		d := S3{URL: parseURL(t, "s3://bucket/x/"), DryRun: true, store: store}
		if err := d.Publish(ctx, writeTree(t, time.Now(), "a")); err != nil {
			t.Fatal(err)
		}
		if len(store.puts) != 0 {
			t.Errorf("sent %v", store.puts)
		}
	})

	t.Run("a dry-run copy needs no AWS config", func(t *testing.T) {
		t.Setenv("AWS_PROFILE", "no-such-profile")
		t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "config"))
		d := S3{URL: parseURL(t, "s3://bucket/x/"), DryRun: true}
		if err := d.Publish(ctx, writeTree(t, time.Now(), "a")); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("an error names the destination", func(t *testing.T) {
		store := newFakeStore(nil)
		store.err = errors.New("denied")
		d := S3{URL: parseURL(t, "s3://bucket/charts/"), store: store}
		err := d.Publish(ctx, writeTree(t, time.Now(), "a"))
		if err == nil || !strings.Contains(err.Error(), "s3://bucket/charts/") {
			t.Errorf("error = %v, want it to name the destination", err)
		}
	})

	t.Run("a URL that is not s3 fails before any copy", func(t *testing.T) {
		store := newFakeStore(nil)
		if err := (S3{URL: parseURL(t, "gs://bucket/x/"), store: store}).Publish(ctx, writeTree(t, time.Now(), "a")); err == nil {
			t.Error("expected an error")
		}
	})
}

func TestGCSPublish(t *testing.T) {
	ctx := context.Background()

	t.Run("sync deletes what the source dropped", func(t *testing.T) {
		store := newFakeStore(map[string]fakeObject{"hash/dropped": {body: "x", modTime: time.Now()}})
		d := GCS{URL: parseURL(t, "gs://bucket/hash"), Sync: true, store: store}
		if err := d.Publish(ctx, writeTree(t, time.Now(), "kept")); err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff([]string{"hash/dropped"}, store.removes); diff != "" {
			t.Errorf("removes (-want +got):\n%s", diff)
		}
		if diff := cmp.Diff([]string{"hash/kept"}, store.puts); diff != "" {
			t.Errorf("puts (-want +got):\n%s", diff)
		}
	})

	t.Run("a copy deletes nothing", func(t *testing.T) {
		store := newFakeStore(map[string]fakeObject{"x/other": {body: "x", modTime: time.Now()}})
		d := GCS{URL: parseURL(t, "gs://bucket/x"), store: store}
		if err := d.Publish(ctx, writeTree(t, time.Now(), "a")); err != nil {
			t.Fatal(err)
		}
		if len(store.removes) != 0 {
			t.Errorf("removed %v", store.removes)
		}
	})

	t.Run("a dry-run copy needs no credentials", func(t *testing.T) {
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "missing.json"))
		d := GCS{URL: parseURL(t, "gs://bucket/x"), DryRun: true}
		if err := d.Publish(ctx, writeTree(t, time.Now(), "a")); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("an error names the destination", func(t *testing.T) {
		store := newFakeStore(nil)
		store.err = errors.New("denied")
		err := (GCS{URL: parseURL(t, "gs://bucket/hash"), store: store}).Publish(ctx, writeTree(t, time.Now(), "a"))
		if err == nil || !strings.Contains(err.Error(), "gs://bucket/hash") {
			t.Errorf("error = %v, want it to name the destination", err)
		}
	})
}

func parseURL(t *testing.T, s string) url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return *u
}
