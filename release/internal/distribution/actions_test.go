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
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

type fakeDest struct {
	name string
	err  error

	mu   sync.Mutex
	srcs []string
}

func (d *fakeDest) Name() string { return d.name }

func (d *fakeDest) Publish(_ context.Context, src string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.srcs = append(d.srcs, src)
	return d.err
}

func (d *fakeDest) got() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.srcs)
}

type fakeRecorder struct {
	refs []string
	err  error
}

func (r *fakeRecorder) Add(refs ...string) error {
	r.refs = append(r.refs, refs...)
	return r.err
}

func dirWith(t *testing.T, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, n := range names {
		path := filepath.Join(dir, n)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("creating %s: %v", path, err)
		}
		if err := os.WriteFile(path, []byte(n), 0o644); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
	}
	return dir
}

func TestBuildMetadata(t *testing.T) {
	dir := t.TempDir()
	m := Metadata{
		Version:         "v3.30.0",
		OperatorVersion: "v1.38.0",
		Images:          []string{"calico/node:v3.30.0"},
		ChartVersion:    "v3.30.0",
	}
	if err := BuildMetadata(m, dir); err != nil {
		t.Fatalf("BuildMetadata: %v", err)
	}

	bs, err := os.ReadFile(filepath.Join(dir, MetadataFileName))
	if err != nil {
		t.Fatalf("reading metadata: %v", err)
	}
	// Pinned to literal keys: a round-trip would pass through a rename.
	for _, want := range []string{"version: v3.30.0", "operatorVersion: v1.38.0", "helmChartVersion: v3.30.0"} {
		if !strings.Contains(string(bs), want) {
			t.Errorf("expected %q in:\n%s", want, bs)
		}
	}
}

func TestBuildMetadataRejectsIncompleteInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    Metadata
		want string
	}{
		{"no version", Metadata{OperatorVersion: "v1", Images: []string{"i"}}, "version"},
		{"no operator version", Metadata{Version: "v1", Images: []string{"i"}}, "operator version"},
		{"no images", Metadata{Version: "v1", OperatorVersion: "v1"}, "images"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := BuildMetadata(tc.m, t.TempDir()); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("expected an error naming %q, got %v", tc.want, err)
			}
		})
	}
}

func TestSHA256SumsSkipsDirectoriesAndItself(t *testing.T) {
	dir := dirWith(t, "release.tgz", "metadata.yaml", "charts/index.yaml")
	if err := os.WriteFile(filepath.Join(dir, SumsFileName), []byte("stale"), 0o644); err != nil {
		t.Fatalf("seeding a stale sums file: %v", err)
	}

	if err := SHA256Sums(dir); err != nil {
		t.Fatalf("SHA256Sums: %v", err)
	}
	bs, err := os.ReadFile(filepath.Join(dir, SumsFileName))
	if err != nil {
		t.Fatalf("reading sums: %v", err)
	}
	got := string(bs)
	for _, want := range []string{"release.tgz", "metadata.yaml"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %s checksummed, got:\n%s", want, got)
		}
	}
	for _, unwanted := range []string{"charts", SumsFileName} {
		if strings.Contains(got, unwanted) {
			t.Errorf("expected %s left out, got:\n%s", unwanted, got)
		}
	}
}

func TestPublishSendsEachSourceToItsDestination(t *testing.T) {
	dir := dirWith(t, "release.tgz", "charts/index.yaml")
	gh := &fakeDest{name: "github"}
	s3 := &fakeDest{name: "s3://bucket/charts/"}

	err := Publish([]Upload{
		{Source: dir, Handler: gh},
		{Source: filepath.Join(dir, "charts"), Handler: s3},
	}, true)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if got := gh.got(); len(got) != 1 || got[0] != dir {
		t.Errorf("github got %v, want [%s]", got, dir)
	}
	if got := s3.got(); len(got) != 1 || got[0] != filepath.Join(dir, "charts") {
		t.Errorf("s3 got %v", got)
	}
}

func TestPublishDryRunSendsNothing(t *testing.T) {
	dir := dirWith(t, "release.tgz")
	d := &fakeDest{name: "github"}
	rec := &fakeRecorder{}

	if err := Publish([]Upload{{Source: dir, Handler: d}}, false, WithRecord(rec)); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if got := d.got(); len(got) != 0 {
		t.Errorf("expected nothing published, got %v", got)
	}
	// Recording a dry run would name artifacts that were never sent.
	if len(rec.refs) != 0 {
		t.Errorf("expected nothing recorded, got %v", rec.refs)
	}
}

func TestPublishMissingSource(t *testing.T) {
	for _, tc := range []struct {
		name    string
		skip    bool
		wantErr string
	}{
		{name: "fails by default", wantErr: "does not exist"},
		{name: "skips when allowed", skip: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &fakeDest{name: "s3://bucket/files/"}
			absent := filepath.Join(t.TempDir(), "never-built")

			err := Publish([]Upload{{Source: absent, Handler: d, Skip: tc.skip}}, true)

			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected an error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Publish: %v", err)
			}
			if got := d.got(); len(got) != 0 {
				t.Errorf("expected the absent source skipped, got %v", got)
			}
		})
	}
}

// A later upload can depend on an earlier one, so a failure stops the list
// rather than publishing against a broken step.
func TestPublishStopsAtTheFirstFailure(t *testing.T) {
	dir := dirWith(t, "release.tgz")
	bad := &fakeDest{name: "s3://bad/", err: errors.New("access denied")}
	after := &fakeDest{name: "github"}

	err := Publish([]Upload{
		{Source: dir, Handler: bad},
		{Source: dir, Handler: after},
	}, true)
	if err == nil || !strings.Contains(err.Error(), "s3://bad/") {
		t.Fatalf("expected the failure reported, got %v", err)
	}
	if got := after.got(); len(got) != 0 {
		t.Errorf("expected nothing published after the failure, got %v", got)
	}
}

func TestPublishRecordsWhatSucceededDespiteAFailure(t *testing.T) {
	dir := dirWith(t, "release.tgz")
	rec := &fakeRecorder{}

	err := Publish([]Upload{
		{Source: dir, Handler: &fakeDest{name: "github"}},
		{Source: dir, Handler: &fakeDest{name: "s3://bad/", err: errors.New("denied")}},
	}, true, WithRecord(rec))
	if err == nil {
		t.Fatal("expected the failure reported")
	}
	if !slices.Contains(rec.refs, "github") {
		t.Errorf("expected the publish recorded, got %v", rec.refs)
	}
}

// A handler with its own rules rejects a bad upload before anything is sent.
func TestPublishRejectsASourcelessUploadToADestinationThatNeedsOne(t *testing.T) {
	err := Publish([]Upload{{Handler: S3{URI: "s3://bucket/charts/"}}}, true)
	if err == nil || !strings.Contains(err.Error(), "no source") {
		t.Errorf("expected a missing source to be rejected, got %v", err)
	}
}

// A handler that finds its own content takes no source, so it runs.
func TestPublishSourcelessHandlerRuns(t *testing.T) {
	d := &fakeDest{name: "images"}
	if err := Publish([]Upload{{Handler: d}}, true); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if got := d.got(); len(got) != 1 || got[0] != "" {
		t.Errorf("expected one call with an empty source, got %v", got)
	}
}

func TestPublishRejectsIncompleteUploads(t *testing.T) {
	for _, tc := range []struct {
		name    string
		uploads []Upload
		want    string
	}{
		{"none", nil, "no uploads"},
		{"no destination", []Upload{{Source: "/tmp"}}, "no destination"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := Publish(tc.uploads, true); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("expected an error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestPublishRetriesBeforeGivingUp(t *testing.T) {
	dir := dirWith(t, "release.tgz")
	d := &flakyDest{failures: 1}

	if err := Publish([]Upload{{Source: dir, Handler: d}}, true); err != nil {
		t.Fatalf("expected the retry to succeed, got %v", err)
	}
	if d.calls != 2 {
		t.Errorf("published %d times, want 2", d.calls)
	}
}

type flakyDest struct {
	failures int
	calls    int
}

func (d *flakyDest) Name() string { return "flaky" }

func (d *flakyDest) Publish(context.Context, string) error {
	d.calls++
	if d.calls <= d.failures {
		return fmt.Errorf("transient failure %d", d.calls)
	}
	return nil
}

// A log reader tells two uploads to one bucket apart by name, so an upload
// with none falls back to its destination rather than logging nothing.
func TestUploadLabel(t *testing.T) {
	for _, tc := range []struct {
		name string
		up   Upload
		want string
	}{
		{"names itself", Upload{Name: "chart index", Handler: S3{URI: "s3://b/charts/"}}, "chart index"},
		{"falls back to the destination", Upload{Handler: S3{URI: "s3://b/charts/"}}, "s3://b/charts/"},
		{"a preparer falls back to its kind", Upload{Handler: Preparer{Kind: "metadata"}}, "metadata"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.up.label(); got != tc.want {
				t.Errorf("label() = %q, want %q", got, tc.want)
			}
		})
	}
}
