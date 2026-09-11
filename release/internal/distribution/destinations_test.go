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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fakeRunner records the command a destination built, so a test asserts on
// the arguments rather than on a bucket.
type fakeRunner struct {
	name string
	args []string
	err  error
}

func (f *fakeRunner) Run(name string, args, _ []string) (string, error) {
	f.name, f.args = name, args
	return "", f.err
}

func (f *fakeRunner) RunInDir(_, name string, args, env []string) (string, error) {
	return f.Run(name, args, env)
}

func (f *fakeRunner) RunInDirToFile(_, name string, args, env []string, _ string) (string, error) {
	return f.Run(name, args, env)
}

func (f *fakeRunner) RunInDirNoCapture(_, name string, args, env []string) error {
	_, err := f.Run(name, args, env)
	return err
}

func (f *fakeRunner) RunNoCapture(name string, args, env []string) error {
	_, err := f.Run(name, args, env)
	return err
}

// The destination stats the source to pick its verb, so a test needs a real
// path rather than a plausible string.
func srcPath(t *testing.T, dir bool) string {
	t.Helper()
	if dir {
		return t.TempDir()
	}
	path := filepath.Join(t.TempDir(), "artifact.tgz")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return path
}

func (f *fakeRunner) has(flag string) bool { return slices.Contains(f.args, flag) }

func (f *fakeRunner) valueAfter(flag string) string {
	if i := slices.Index(f.args, flag); i >= 0 && i+1 < len(f.args) {
		return f.args[i+1]
	}
	return ""
}

// An artifact users download must be readable, so the ACL is the default and
// a private upload is what has to be asked for. Getting this the wrong way
// round uploads successfully and leaves the object unreadable.
func TestS3PublicReadIsTheDefault(t *testing.T) {
	for _, tc := range []struct {
		name    string
		private bool
		wantACL bool
	}{
		{name: "public by default", wantACL: true},
		{name: "private when asked", private: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeRunner{}
			d := S3{URI: "s3://bucket/charts/", Private: tc.private, Runner: f}
			if err := d.Publish(context.Background(), srcPath(t, true)); err != nil {
				t.Fatalf("Publish: %v", err)
			}
			if got := f.has("--acl"); got != tc.wantACL {
				t.Errorf("--acl present = %v, want %v (args %v)", got, tc.wantACL, f.args)
			}
			if tc.wantACL && f.valueAfter("--acl") != "public-read" {
				t.Errorf("--acl = %q, want public-read", f.valueAfter("--acl"))
			}
		})
	}
}

func TestS3Verb(t *testing.T) {
	for _, tc := range []struct {
		name     string
		sync     bool
		dir      bool
		wantVerb string
		wantRec  bool
	}{
		{name: "copies a file", wantVerb: "cp"},
		{name: "copies a directory recursively", dir: true, wantVerb: "cp", wantRec: true},
		// sync descends on its own, and rejects --recursive.
		{name: "syncs a tree", sync: true, dir: true, wantVerb: "sync"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeRunner{}
			d := S3{URI: "s3://bucket/x/", Sync: tc.sync, Runner: f}
			if err := d.Publish(context.Background(), srcPath(t, tc.dir)); err != nil {
				t.Fatalf("Publish: %v", err)
			}
			if f.name != "aws" {
				t.Errorf("ran %q, want aws", f.name)
			}
			if !f.has(tc.wantVerb) {
				t.Errorf("verb = %v, want %s", f.args, tc.wantVerb)
			}
			if got := f.has("--recursive"); got != tc.wantRec {
				t.Errorf("--recursive = %v, want %v (args %v)", got, tc.wantRec, f.args)
			}
		})
	}
}

func TestS3ProfileOnlyWhenSet(t *testing.T) {
	f := &fakeRunner{}
	if err := (S3{URI: "s3://b/x/", Runner: f}).Publish(context.Background(), srcPath(t, false)); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if f.has("--profile") {
		t.Errorf("expected no --profile when unset, got %v", f.args)
	}

	f = &fakeRunner{}
	if err := (S3{URI: "s3://b/x/", Profile: "release", Runner: f}).Publish(context.Background(), srcPath(t, false)); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if f.valueAfter("--profile") != "release" {
		t.Errorf("--profile = %q, want release", f.valueAfter("--profile"))
	}
}

func TestGCSSyncDeletesWhatTheSourceDropped(t *testing.T) {
	f := &fakeRunner{}
	d := GCS{URI: "gs://bucket/hash", Sync: true, Runner: f}
	if err := d.Publish(context.Background(), srcPath(t, true)); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if f.name != "gcloud" {
		t.Errorf("ran %q, want gcloud", f.name)
	}
	for _, want := range []string{"rsync", "--recursive", "--delete-unmatched-destination-objects"} {
		if !f.has(want) {
			t.Errorf("expected %s in %v", want, f.args)
		}
	}
}

// A dry run must reach no bucket at all, rather than passing a flag the
// gcloud verb may not accept.
func TestGCSDryRunRunsNothing(t *testing.T) {
	f := &fakeRunner{}
	d := GCS{URI: "gs://bucket/x", DryRun: true, Runner: f}
	if err := d.Publish(context.Background(), srcPath(t, false)); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if f.name != "" {
		t.Errorf("expected no command run, got %q %v", f.name, f.args)
	}
}

func TestDestinationNames(t *testing.T) {
	if got := (S3{URI: "s3://b/k/"}).Name(); got != "s3://b/k/" {
		t.Errorf("S3 name = %q", got)
	}
	if got := (GCS{URI: "gs://b/k"}).Name(); got != "gs://b/k" {
		t.Errorf("GCS name = %q", got)
	}
	if got := (GithubRelease{Tag: "v3.30.0"}).Name(); !strings.Contains(got, "v3.30.0") {
		t.Errorf("github name = %q, want the tag in it", got)
	}
}
