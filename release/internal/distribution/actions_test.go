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

func TestPublishSendsEachSourceToItsDestination(t *testing.T) {
	dir := dirWith(t, "release.tgz", "charts/index.yaml")
	gh := &fakeDest{name: "github"}
	s3 := &fakeDest{name: "s3://bucket/charts/"}

	err := Publish([]Upload{
		{Source: dir, Handler: gh},
		{Source: filepath.Join(dir, "charts"), Handler: s3},
	})
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

// A dry run still runs every step, so it exercises everything a real run
// does except the remote write — which each handler suppresses itself.
func TestPublishDryRunStillRunsTheSteps(t *testing.T) {
	dir := dirWith(t, "release.tgz")
	d := &fakeDest{name: "github"}

	if err := Publish([]Upload{{Source: dir, Handler: d}}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if got := d.got(); len(got) != 1 {
		t.Errorf("expected the handler run, got %v", got)
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

			err := Publish([]Upload{{Source: absent, Handler: d, Skip: tc.skip}})

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
	})
	if err == nil || !strings.Contains(err.Error(), "s3://bad/") {
		t.Fatalf("expected the failure reported, got %v", err)
	}
	if got := after.got(); len(got) != 0 {
		t.Errorf("expected nothing published after the failure, got %v", got)
	}
}

// A handler with its own rules rejects a bad upload before anything is sent.
func TestPublishRejectsASourcelessUploadToADestinationThatNeedsOne(t *testing.T) {
	err := Publish([]Upload{{Handler: S3{URI: "s3://bucket/charts/"}}})
	if err == nil || !strings.Contains(err.Error(), "no source") {
		t.Errorf("expected a missing source to be rejected, got %v", err)
	}
}

// A handler that finds its own content takes no source, so it runs.
func TestPublishSourcelessHandlerRuns(t *testing.T) {
	d := &fakeDest{name: "images"}
	if err := Publish([]Upload{{Handler: d}}); err != nil {
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
			if err := Publish(tc.uploads); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("expected an error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestPublishRetriesBeforeGivingUp(t *testing.T) {
	dir := dirWith(t, "release.tgz")
	d := &flakyDest{failures: 1}

	if err := Publish([]Upload{{Source: dir, Handler: d}}); err != nil {
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

// A skipped upload never runs, so it has nothing for a handler's rules to
// object to.
func TestPublishSkipsValidationOfASkippedUpload(t *testing.T) {
	d := &fakeDest{name: "s3://bucket/rpms/"}
	if err := Publish([]Upload{
		{Handler: S3{URI: "s3://bucket/rpms/"}, Skip: true},
		{Source: dirWith(t, "x"), Handler: d},
	}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if got := d.got(); len(got) != 1 {
		t.Errorf("expected the unskipped upload to run, got %v", got)
	}
}

// attestation is a product's record: it validates itself and marshals itself,
// and the verb writes whatever bytes it hands back.
type attestation struct {
	body []byte
	err  error
}

func (a attestation) Attest() ([]byte, error) { return a.body, a.err }

func TestBuildMetadata(t *testing.T) {
	dir := t.TempDir()
	if err := BuildMetadata(attestation{body: []byte("version: v3.30.0\n")}, dir); err != nil {
		t.Fatalf("BuildMetadata: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, MetadataFileName))
	if err != nil {
		t.Fatalf("reading metadata: %v", err)
	}
	if string(got) != "version: v3.30.0\n" {
		t.Errorf("wrote %q, want the bytes the record produced", got)
	}
}

// A record that cannot vouch for itself is not written at all, rather than
// leaving a half-filled file for a consumer to read.
func TestBuildMetadataWritesNothingWhenTheRecordFails(t *testing.T) {
	dir := t.TempDir()
	err := BuildMetadata(attestation{err: errors.New("no version specified")}, dir)
	if err == nil || !strings.Contains(err.Error(), "no version specified") {
		t.Fatalf("expected the record's own error, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, MetadataFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected no file written, got %v", err)
	}
}

func TestBuildMetadataNeedsADirectory(t *testing.T) {
	if err := BuildMetadata(attestation{body: []byte("x")}, ""); err == nil {
		t.Error("expected an error with no directory to write to")
	}
}
