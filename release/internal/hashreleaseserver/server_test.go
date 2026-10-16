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

package hashreleaseserver

import (
	"context"
	"errors"
	"testing"
)

type fakeObject struct {
	data       []byte
	generation int64
}

// fakeObjects keeps generations the way Cloud Storage does. beforeWrite, when
// set, runs between a read and the write that follows it, as a concurrent
// publish would.
type fakeObjects struct {
	objects     map[string]fakeObject
	readErr     error
	writeErr    error
	writes      int
	beforeWrite func(f *fakeObjects)
}

func (f *fakeObjects) Read(_ context.Context, name string) ([]byte, int64, error) {
	if f.readErr != nil {
		return nil, 0, f.readErr
	}
	o := f.objects[name]
	return o.data, o.generation, nil
}

func (f *fakeObjects) Write(_ context.Context, name string, data []byte, generation int64) error {
	if hook := f.beforeWrite; hook != nil {
		f.beforeWrite = nil
		hook(f)
	}
	if f.writeErr != nil {
		return f.writeErr
	}
	current := f.objects[name]
	if generation != anyGeneration && generation != current.generation {
		return errChanged
	}
	f.put(name, string(data))
	return nil
}

func (f *fakeObjects) put(name, data string) {
	if f.objects == nil {
		f.objects = map[string]fakeObject{}
	}
	f.writes++
	f.objects[name] = fakeObject{data: []byte(data), generation: f.objects[name].generation + 1}
}

func (f *fakeObjects) get(name string) string { return string(f.objects[name].data) }

func record(t *testing.T, objs *fakeObjects, rel Hashrelease) error {
	t.Helper()
	return Record("os", &rel, &Config{BucketName: "b", objs: objs})
}

func TestRecordStartsTheLibrary(t *testing.T) {
	objs := &fakeObjects{}
	if err := record(t, objs, Hashrelease{Hash: "v3.31.0-v1.40.0", Note: "first"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if got, want := objs.get(releaseLibFileName), "v3.31.0-v1.40.0 - first \n"; got != want {
		t.Errorf("library = %q, want %q", got, want)
	}
}

func TestRecordAppendsToTheLibrary(t *testing.T) {
	objs := &fakeObjects{}
	objs.put(releaseLibFileName, "a - one \nb - two \n\n")
	if err := record(t, objs, Hashrelease{Hash: "c", Note: "three"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if got, want := objs.get(releaseLibFileName), "a - one \nb - two \nc - three \n"; got != want {
		t.Errorf("library = %q, want %q", got, want)
	}
}

// Two publishes at once must both land: the second writer starts over from
// what the first wrote rather than overwriting it.
func TestRecordKeepsAConcurrentEntry(t *testing.T) {
	objs := &fakeObjects{beforeWrite: func(f *fakeObjects) {
		f.put(releaseLibFileName, f.get(releaseLibFileName)+"other - concurrent \n")
	}}
	objs.put(releaseLibFileName, "a - one \n")
	if err := record(t, objs, Hashrelease{Hash: "mine", Note: "this"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if got, want := objs.get(releaseLibFileName), "a - one \nother - concurrent \nmine - this \n"; got != want {
		t.Errorf("library = %q, want %q", got, want)
	}
}

// A library that cannot be read must be left alone, never replaced by just
// the new entry or by nothing.
func TestRecordWritesNothingWhenTheLibraryCannotBeRead(t *testing.T) {
	objs := &fakeObjects{}
	objs.put(releaseLibFileName, "a - one \n")
	objs.readErr = errors.New("transient")
	writes := objs.writes
	if err := record(t, objs, Hashrelease{Hash: "b"}); err == nil {
		t.Fatal("expected the read failure reported")
	}
	if objs.writes != writes {
		t.Errorf("wrote %d times after a failed read, want none", objs.writes-writes)
	}
	if got := objs.get(releaseLibFileName); got != "a - one \n" {
		t.Errorf("library = %q, want it unchanged", got)
	}
}

func TestRecordReportsAFailedWrite(t *testing.T) {
	objs := &fakeObjects{writeErr: errors.New("denied")}
	if err := record(t, objs, Hashrelease{Hash: "b"}); err == nil {
		t.Fatal("expected the write failure reported")
	}
}

func TestRecordGivesUpWhenTheLibraryKeepsChanging(t *testing.T) {
	objs := &fakeObjects{}
	var churn func(f *fakeObjects)
	churn = func(f *fakeObjects) {
		f.put(releaseLibFileName, f.get(releaseLibFileName)+"x - churn \n")
		f.beforeWrite = churn
	}
	objs.beforeWrite = churn
	err := record(t, objs, Hashrelease{Hash: "b"})
	if !errors.Is(err, errChanged) {
		t.Fatalf("Record = %v, want errChanged after %d attempts", err, maxAppendAttempts)
	}
}

func TestRecordPointsLatestAtTheHashrelease(t *testing.T) {
	objs := &fakeObjects{}
	rel := Hashrelease{Name: "2026-10-16-v3-31-orange", Hash: "h", Stream: "v3.31", Latest: true}
	if err := record(t, objs, rel); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if got, want := objs.get("latest-os/v3.31.txt"), "https://2026-10-16-v3-31-orange."+BaseDomain+"/"; got != want {
		t.Errorf("latest = %q, want %q", got, want)
	}
}

// A hash is a dash-joined list of versions, so one can be a prefix of
// another, and a note can mention one.
func TestHasHashreleaseMatchesTheWholeHash(t *testing.T) {
	objs := &fakeObjects{}
	objs.put(releaseLibFileName, "v3.31.0-v1.40.1 - built from v3.31.0-v1.39.0 \n")
	cfg := &Config{BucketName: "b", objs: objs}
	for hash, want := range map[string]bool{
		"v3.31.0-v1.40.1": true,
		"v3.31.0-v1.40":   false,
		"v3.31.0-v1.39.0": false,
		"-":               false,
	} {
		got, err := HasHashrelease(hash, cfg)
		if err != nil {
			t.Fatalf("HasHashrelease(%q): %v", hash, err)
		}
		if got != want {
			t.Errorf("HasHashrelease(%q) = %v, want %v", hash, got, want)
		}
	}
}

func TestHasHashreleaseWithNoLibrary(t *testing.T) {
	got, err := HasHashrelease("h", &Config{BucketName: "b", objs: &fakeObjects{}})
	if err != nil || got {
		t.Errorf("HasHashrelease = %v, %v, want false, nil", got, err)
	}
}
