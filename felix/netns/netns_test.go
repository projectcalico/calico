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

package netns

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestFindPodPID(t *testing.T) {
	tmp := t.TempDir()

	const podUID = "9f6e3c84-1234-4abc-9999-aabbccddeeff"
	// systemd driver replaces dashes with underscores in the pod
	// slice name.
	systemdForm := "9f6e3c84_1234_4abc_9999_aabbccddeeff"

	cases := []struct {
		name        string
		pid         int
		cgroup      string
		shouldMatch bool
	}{
		{
			name:        "cgroupfs-v2-dashes",
			pid:         101,
			cgroup:      "0::/kubepods/burstable/pod" + podUID + "/abc\n",
			shouldMatch: true,
		},
		{
			name:        "systemd-v2-underscores",
			pid:         202,
			cgroup:      "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + systemdForm + ".slice/cri-containerd-deadbeef.scope\n",
			shouldMatch: true,
		},
		{
			name:        "cgroupfs-v1-dashes",
			pid:         303,
			cgroup:      "11:pids:/kubepods/besteffort/pod" + podUID + "/xyz\n",
			shouldMatch: true,
		},
		{
			name:        "unrelated-process",
			pid:         404,
			cgroup:      "0::/init.scope\n",
			shouldMatch: false,
		},
	}

	// Lay out the fake /proc tree.
	for _, c := range cases {
		dir := filepath.Join(tmp, strconv.Itoa(c.pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(c.cgroup), 0o644); err != nil {
			t.Fatalf("write cgroup file: %v", err)
		}
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// findPodPID returns the *first* PID it finds whose
			// cgroup matches. In a per-subtest scenario we don't
			// strictly assert that a specific PID is found — only
			// that the search succeeds or fails as expected when
			// only this PID could match.
			pid, err := findPodPIDOnly(podUID, tmp, c.pid)
			if c.shouldMatch {
				if err != nil {
					t.Fatalf("expected match, got error: %v", err)
				}
				if pid != c.pid {
					t.Fatalf("got pid %d, want %d", pid, c.pid)
				}
			} else {
				if err == nil {
					t.Fatalf("expected no match, got pid %d", pid)
				}
			}
		})
	}
}

// findPodPIDOnly is a test helper: rebuilds /proc with only the named
// PID present so findPodPID's "first match wins" behavior is
// deterministic regardless of ordering across subtests.
func findPodPIDOnly(podUID, root string, keepPID int) (int, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0, err
	}
	keep := strconv.Itoa(keepPID)
	for _, e := range entries {
		if e.Name() == keep {
			continue
		}
		// Hide other PID dirs by renaming the cgroup file so the
		// path-walk in findPodPID can't read it.
		path := filepath.Join(root, e.Name(), "cgroup")
		if _, err := os.Stat(path); err == nil {
			if err := os.Rename(path, path+".hidden"); err != nil {
				return 0, fmt.Errorf("hiding %s: %w", path, err)
			}
		}
	}
	// Restore on exit so the next subtest's PID isn't accidentally
	// masked.
	defer func() {
		for _, e := range entries {
			if e.Name() == keep {
				continue
			}
			path := filepath.Join(root, e.Name(), "cgroup.hidden")
			if _, err := os.Stat(path); err == nil {
				_ = os.Rename(path, filepath.Join(root, e.Name(), "cgroup"))
			}
		}
	}()
	return findPodPID(root, podUID)
}

func TestResolvePodNetnsPaths_Batched(t *testing.T) {
	tmp := t.TempDir()

	const (
		uidA = "aaaaaaaa-1111-4abc-9999-aaaaaaaaaaaa" // cgroupfs dash form
		uidB = "bbbbbbbb-2222-4abc-9999-bbbbbbbbbbbb" // systemd underscore form
		uidC = "cccccccc-3333-4abc-9999-cccccccccccc" // no live process
	)
	uidBUnderscore := "bbbbbbbb_2222_4abc_9999_bbbbbbbbbbbb"

	procs := map[int]string{
		101: "0::/kubepods/burstable/pod" + uidA + "/abc\n",
		202: "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + uidBUnderscore + ".slice/cri-containerd-x.scope\n",
		303: "0::/init.scope\n", // unrelated
	}
	for pid, cg := range procs {
		dir := filepath.Join(tmp, strconv.Itoa(pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(cg), 0o644); err != nil {
			t.Fatalf("write cgroup: %v", err)
		}
	}

	got := ResolvePodNetnsPaths(tmp, []string{uidA, uidB, uidC})
	if len(got) != 2 {
		t.Fatalf("expected 2 resolved paths, got %d: %v", len(got), got)
	}
	if want := filepath.Join(tmp, "101", "ns", "net"); got[uidA] != want {
		t.Errorf("uidA: got %q, want %q", got[uidA], want)
	}
	if want := filepath.Join(tmp, "202", "ns", "net"); got[uidB] != want {
		t.Errorf("uidB: got %q, want %q", got[uidB], want)
	}
	if _, ok := got[uidC]; ok {
		t.Errorf("uidC has no live process; should be omitted, got %q", got[uidC])
	}

	// Empty / blank input is ignored, not an error.
	if got := ResolvePodNetnsPaths(tmp, nil); len(got) != 0 {
		t.Errorf("nil input: expected empty, got %v", got)
	}
	if got := ResolvePodNetnsPaths(tmp, []string{"", ""}); len(got) != 0 {
		t.Errorf("blank UIDs: expected empty, got %v", got)
	}
}

func TestResolvePodCookie_EmptyUID(t *testing.T) {
	if _, err := ResolvePodCookie("/proc", ""); err == nil {
		t.Fatalf("expected error for empty UID")
	}
}

func TestHostPath(t *testing.T) {
	// hostPath() rewrites absolute host paths under hostMountRoot(procRoot)
	// (<procRoot>/1/root) using SecureJoin. With no symlinks present under
	// that (non-existent, in tests) root, SecureJoin yields the same clean
	// result as a naive prefix, so we assert against that.
	const procRoot = "/host/proc"
	root := hostMountRoot(procRoot)
	cases := []struct {
		in, want string
	}{
		{"/run/netns/cni-X", root + "/run/netns/cni-X"},
		{"", ""},
		{"relative/path", "relative/path"},
		{root + "/already/prefixed", root + "/already/prefixed"},
	}
	for _, c := range cases {
		if got := hostPath(procRoot, c.in); got != c.want {
			t.Errorf("hostPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNetnsCookieSelf(t *testing.T) {
	// Verifies the netns-cookie read path against our own netns.
	// We don't compare against a known value (it's kernel-assigned)
	// but the call should succeed and return non-zero on any kernel
	// >= 5.12 with SO_NETNS_COOKIE.
	cookie, err := netnsCookie("/proc/self/ns/net")
	if err != nil {
		t.Skipf("netnsCookie on self failed (likely older kernel without SO_NETNS_COOKIE): %v", err)
	}
	if cookie == 0 {
		t.Fatalf("expected non-zero netns cookie for self netns")
	}
}
