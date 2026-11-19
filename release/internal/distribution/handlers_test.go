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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestDestinationNames(t *testing.T) {
	if got := (S3{URI: "s3://b/k/"}).Name(); got != "s3://b/k/" {
		t.Errorf("S3 name = %q", got)
	}
	if got := (GCS{URI: "gs://b/k"}).Name(); got != "gs://b/k" {
		t.Errorf("GCS name = %q", got)
	}
}

func TestS3Publish(t *testing.T) {
	ctx := context.Background()

	t.Run("excludes then includes, as aws did", func(t *testing.T) {
		store := newFakeStore(nil)
		d := S3{URI: "s3://bucket/debs/", Exclude: []string{"*"}, Include: []string{"dists/*"}, store: store}
		if err := d.Publish(ctx, writeTree(t, time.Now(), "pool/a.deb", "dists/Release")); err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff([]string{"debs/dists/Release"}, store.puts); diff != "" {
			t.Errorf("puts (-want +got):\n%s", diff)
		}
	})

	t.Run("sync never deletes", func(t *testing.T) {
		store := newFakeStore(map[string]fakeObject{"x/old": {body: "old", modTime: time.Now()}})
		d := S3{URI: "s3://bucket/x/", Sync: true, store: store}
		if err := d.Publish(ctx, writeTree(t, time.Now(), "new")); err != nil {
			t.Fatal(err)
		}
		if len(store.removes) != 0 {
			t.Errorf("removed %v", store.removes)
		}
	})

	t.Run("a dry run sends nothing", func(t *testing.T) {
		store := newFakeStore(nil)
		d := S3{URI: "s3://bucket/x/", DryRun: true, store: store}
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
		d := S3{URI: "s3://bucket/x/", DryRun: true}
		if err := d.Publish(ctx, writeTree(t, time.Now(), "a")); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("an error names the destination", func(t *testing.T) {
		store := newFakeStore(nil)
		store.err = errors.New("denied")
		d := S3{URI: "s3://bucket/charts/", store: store}
		err := d.Publish(ctx, writeTree(t, time.Now(), "a"))
		if err == nil || !strings.Contains(err.Error(), "s3://bucket/charts/") {
			t.Errorf("error = %v, want it to name the destination", err)
		}
	})

	t.Run("a URI that is not s3 fails before any copy", func(t *testing.T) {
		store := newFakeStore(nil)
		if err := (S3{URI: "gs://bucket/x/", store: store}).Publish(ctx, writeTree(t, time.Now(), "a")); err == nil {
			t.Error("expected an error")
		}
	})
}

func TestGCSPublish(t *testing.T) {
	ctx := context.Background()

	t.Run("sync deletes what the source dropped", func(t *testing.T) {
		store := newFakeStore(map[string]fakeObject{"hash/dropped": {body: "x", modTime: time.Now()}})
		d := GCS{URI: "gs://bucket/hash", Sync: true, store: store}
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
		d := GCS{URI: "gs://bucket/x", store: store}
		if err := d.Publish(ctx, writeTree(t, time.Now(), "a")); err != nil {
			t.Fatal(err)
		}
		if len(store.removes) != 0 {
			t.Errorf("removed %v", store.removes)
		}
	})

	t.Run("a dry-run copy needs no credentials", func(t *testing.T) {
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "missing.json"))
		d := GCS{URI: "gs://bucket/x", DryRun: true}
		if err := d.Publish(ctx, writeTree(t, time.Now(), "a")); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("an error names the destination", func(t *testing.T) {
		store := newFakeStore(nil)
		store.err = errors.New("denied")
		err := (GCS{URI: "gs://bucket/hash", store: store}).Publish(ctx, writeTree(t, time.Now(), "a"))
		if err == nil || !strings.Contains(err.Error(), "gs://bucket/hash") {
			t.Errorf("error = %v, want it to name the destination", err)
		}
	})
}
