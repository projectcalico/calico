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

package gce

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/api/googleapi"
)

// The family path always yields the newest member, so pinning an exact image is
// the only way a job can hold one steady while newer releases land in the family.
func TestSourceImage(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "family when no exact image is given",
			cfg:  Config{ImageProject: "unique-caldron-775", ImageFamily: "ci-base"},
			want: "projects/unique-caldron-775/global/images/family/ci-base",
		},
		{
			name: "exact image when given",
			cfg: Config{
				ImageProject: "unique-caldron-775",
				ImageFamily:  "ci-base",
				Image:        "ci-base-1-27-0-llvm21-1-8-k8s1-37-0",
			},
			want: "projects/unique-caldron-775/global/images/ci-base-1-27-0-llvm21-1-8-k8s1-37-0",
		},
		{
			name: "exact image wins over the family",
			cfg: Config{
				ImageProject: "ubuntu-os-cloud",
				ImageFamily:  "ubuntu-2404-lts-amd64",
				Image:        "ubuntu-2404-noble-amd64-v20260101",
			},
			want: "projects/ubuntu-os-cloud/global/images/ubuntu-2404-noble-amd64-v20260101",
		},
	} {
		if got := sourceImage(tc.cfg); got != tc.want {
			t.Errorf("%s: sourceImage() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// instanceSpec is what actually reaches the API, so make sure the pin survives it.
func TestInstanceSpecUsesPinnedImage(t *testing.T) {
	c := &Client{project: "unique-caldron-775"}
	inst := c.instanceSpec("us-central1-a", Config{
		Name:         "vm",
		MachineType:  "n2-standard-16",
		DiskType:     "pd-ssd",
		DiskSizeGB:   200,
		ImageProject: "unique-caldron-775",
		ImageFamily:  "ci-base",
		Image:        "ci-base-1-27-0-llvm21-1-8-k8s1-37-0",
	})
	got := inst.Disks[0].InitializeParams.SourceImage
	want := "projects/unique-caldron-775/global/images/ci-base-1-27-0-llvm21-1-8-k8s1-37-0"
	if got != want {
		t.Errorf("SourceImage = %q, want %q", got, want)
	}
}

func TestCreateRejectsEmptyZoneList(t *testing.T) {
	c := &Client{project: "p"}
	if _, err := c.Create(context.Background(), Config{Name: "vm"}); err == nil {
		t.Fatal("want an error when no zones are configured")
	}
}

// A dead context must not be reported as a per-zone failure: that is what made the
// original bug unreadable, with the last zone blamed for a deadline an earlier zone
// had already consumed. Every zone should say it was not attempted, and none should
// reach the API.
func TestCreateReportsUnattemptedZonesSeparately(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// svc is nil: if any zone reached the API this would panic, which is the point.
	c := &Client{project: "p"}
	_, err := c.Create(ctx, Config{Name: "vm", Zones: []string{"z-a", "z-b", "z-c"}})
	if err == nil {
		t.Fatal("want an error")
	}
	got := err.Error()
	for _, z := range []string{"z-a", "z-b", "z-c"} {
		if !strings.Contains(got, z+": not attempted") {
			t.Errorf("error should name %s as not attempted; got: %s", z, got)
		}
	}
}

// Delete treats a not-found instance as already deleted, so this decides whether
// a cleanup step is idempotent or spuriously fails.
func TestIsNotFound(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"googleapi 404", &googleapi.Error{Code: 404, Message: "not found"}, true},
		{"googleapi 404 wrapped", fmt.Errorf("delete vm: %w", &googleapi.Error{Code: 404}), true},
		{"googleapi 403", &googleapi.Error{Code: 403, Message: "forbidden"}, false},
		{"googleapi 500", &googleapi.Error{Code: 500}, false},
		// A permission error whose prose happens to contain the old sentinel must
		// not be read as "already gone", or cleanup would silently skip a live VM.
		{"prose mentioning notFound", errors.New("caller lacks permission; resource notFound checks disabled"), false},
		{"unrelated", errors.New("connection reset"), false},
	} {
		if got := isNotFound(tc.err); got != tc.want {
			t.Errorf("%s: isNotFound = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The case this exists for: an insert that outlived PerZoneTimeout leaves a VM in
// one zone -- possibly with a delete queued behind the wedged insert -- while
// Create succeeds in the next. Names are only zone-unique, so both exist.
//
// requireLive is the caller's intent: a run step must not be handed a VM that is
// shutting down, while cleanup is happy to reap one.
func TestPickZone(t *testing.T) {
	for _, tc := range []struct {
		name        string
		found       []zoneInstance
		wantLive    string // requireLive=true; "" with wantLiveErr=false means not found
		wantLiveErr bool
		wantAny     string // requireLive=false
		wantAnyErr  bool
	}{
		{
			name: "nothing found",
		},
		{
			name:     "one running",
			found:    []zoneInstance{{"us-central1-b", "RUNNING"}},
			wantLive: "us-central1-b",
			wantAny:  "us-central1-b",
		},
		{
			name: "abandoned one going away, real one live",
			found: []zoneInstance{
				{"us-central1-a", "STOPPING"},
				{"us-central1-b", "RUNNING"},
			},
			wantLive: "us-central1-b",
			wantAny:  "us-central1-b",
		},
		{
			// A wedged insert can still report STAGING, so both count as live.
			name: "two live is genuine ambiguity either way",
			found: []zoneInstance{
				{"us-central1-a", "STAGING"},
				{"us-central1-b", "RUNNING"},
			},
			wantLiveErr: true,
			wantAnyErr:  true,
		},
		{
			// The correction: a dying VM is never a place to run a job. Cleanup still
			// wants it -- stopped, but holding its disk.
			name:        "only a terminated one",
			found:       []zoneInstance{{"us-central1-a", "TERMINATED"}},
			wantLiveErr: true,
			wantAny:     "us-central1-a",
		},
		{
			name:        "only a stopping one",
			found:       []zoneInstance{{"us-central1-f", "STOPPING"}},
			wantLiveErr: true,
			wantAny:     "us-central1-f",
		},
		{
			// The compute API lists STOPPED as well as TERMINATED for a halted VM.
			name:        "only a stopped one",
			found:       []zoneInstance{{"us-central1-c", "STOPPED"}},
			wantLiveErr: true,
			wantAny:     "us-central1-c",
		},
		{
			// The case this whole split exists for: DEPROVISIONING is what the orphan
			// reports while its queued DELETE finally runs. Counting it live made this
			// ambiguous, so runonvm exited 1 with a good VM sitting right there.
			name: "orphan tearing down, real one live",
			found: []zoneInstance{
				{"us-central1-a", "DEPROVISIONING"},
				{"us-central1-b", "RUNNING"},
			},
			wantLive: "us-central1-b",
			wantAny:  "us-central1-b",
		},
		{
			name:        "only one gracefully shutting down",
			found:       []zoneInstance{{"us-central1-f", "PENDING_STOP"}},
			wantLiveErr: true,
			wantAny:     "us-central1-f",
		},
		{
			name: "two going away: nothing to run on, and ambiguous to reap",
			found: []zoneInstance{
				{"us-central1-a", "TERMINATED"},
				{"us-central1-f", "STOPPING"},
			},
			wantLiveErr: true,
			wantAnyErr:  true,
		},
	} {
		for _, mode := range []struct {
			requireLive bool
			want        string
			wantErr     bool
			label       string
		}{
			{true, tc.wantLive, tc.wantLiveErr, "requireLive"},
			{false, tc.wantAny, tc.wantAnyErr, "any"},
		} {
			got, err := pickZone("vm-1", tc.found, mode.requireLive)
			switch {
			case mode.wantErr && err == nil:
				t.Errorf("%s [%s]: want an error, got zone %q", tc.name, mode.label, got)
			case !mode.wantErr && err != nil:
				t.Errorf("%s [%s]: unexpected error %v", tc.name, mode.label, err)
			case !mode.wantErr && got != mode.want:
				t.Errorf("%s [%s]: got %q, want %q", tc.name, mode.label, got, mode.want)
			}
		}
	}
}

// A refusal has to say which zones and what state, or the operator cannot act.
func TestPickZoneErrorsAreActionable(t *testing.T) {
	_, err := pickZone("vm-1", []zoneInstance{
		{"us-central1-b", "RUNNING"},
		{"us-central1-a", "STAGING"},
	}, true)
	if err == nil {
		t.Fatal("want an error for two live instances")
	}
	for _, want := range []string{"vm-1", "us-central1-a=STAGING", "us-central1-b=RUNNING", "set ZONE"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("ambiguity error should mention %q: %v", want, err)
		}
	}

	_, err = pickZone("vm-1", []zoneInstance{{"us-central1-a", "STOPPING"}}, true)
	if err == nil {
		t.Fatal("want an error when the only instance is dying")
	}
	for _, want := range []string{"vm-1", "not usable", "us-central1-a=STOPPING"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("unusable error should mention %q: %v", want, err)
		}
	}
}

// goingAway is a denylist over Instance.Status, so a value the SDK defines but
// this switch omits silently counts as usable. Pin the whole enum.
func TestGoingAwayCoversTheStatusEnum(t *testing.T) {
	// google.golang.org/api/compute/v1, the Instance.Status doc comment.
	usable := []string{"PENDING", "PROVISIONING", "STAGING", "RUNNING", "REPAIRING"}
	dying := []string{
		"STOPPING", "STOPPED", "SUSPENDING", "SUSPENDED", "TERMINATED",
		"DEPROVISIONING", "PENDING_STOP",
	}
	for _, s := range usable {
		if goingAway(s) {
			t.Errorf("%s is usable or may become so, but goingAway says otherwise", s)
		}
	}
	for _, s := range dying {
		if !goingAway(s) {
			t.Errorf("%s will never become usable, but goingAway treats it as live", s)
		}
	}
	if got := len(usable) + len(dying); got != 12 {
		t.Errorf("Instance.Status has 12 values in the pinned SDK; this test covers %d", got)
	}
}
