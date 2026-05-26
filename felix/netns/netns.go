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
	"runtime"
	"strconv"
	"strings"

	"github.com/containernetworking/plugins/pkg/ns"
	securejoin "github.com/cyphar/filepath-securejoin"
	"golang.org/x/sys/unix"
)

// procRoot is the path to procfs. Overridable for tests.
var procRoot = "/proc"

// ResolvePodNetnsPath finds the netns path of a pod via a
// /proc-cgroup scan. Returns /proc/<pid>/ns/net for any live process
// whose cgroup path mentions the pod UID.
//
// Works regardless of cgroup version because it keys off the pod UID
// embedded in any host process's cgroup path. The pod UID appears
// either with dashes (cgroupfs driver) or with dashes replaced by
// underscores (systemd driver); both forms are searched.
//
// Returns an error if no live process can be found for the pod.
func ResolvePodNetnsPath(podUID string) (string, error) {
	if podUID == "" {
		return "", fmt.Errorf("empty pod UID")
	}
	pid, err := findPodPID(podUID)
	if err != nil {
		return "", fmt.Errorf("finding pid for pod %s: %w", podUID, err)
	}
	return filepath.Join(procRoot, strconv.Itoa(pid), "ns", "net"), nil
}

// ResolvePodNetnsPaths is the batched form of ResolvePodNetnsPath: it
// resolves netns paths for many pod UIDs in a single /proc walk. The
// returned map contains an entry (uid -> /proc/<pid>/ns/net) only for
// the UIDs that matched a live process; UIDs with no live process are
// omitted rather than erroring.
//
// The background resolver in netnsManager uses this so a start-of-day
// burst of unresolved pods costs one O(processes) scan per cycle rather
// than one per pod. Empty/blank UIDs are ignored.
func ResolvePodNetnsPaths(podUIDs []string) map[string]string {
	pids := findPodPIDs(podUIDs)
	if len(pids) == 0 {
		return nil
	}
	paths := make(map[string]string, len(pids))
	for uid, pid := range pids {
		paths[uid] = filepath.Join(procRoot, strconv.Itoa(pid), "ns", "net")
	}
	return paths
}

// ResolvePodCookie is a convenience wrapper that resolves the netns
// path via ResolvePodNetnsPath and reads the cookie via the resulting
// path. Callers that only need the path should call
// ResolvePodNetnsPath directly.
func ResolvePodCookie(podUID string) (uint64, error) {
	netnsPath, err := ResolvePodNetnsPath(podUID)
	if err != nil {
		return 0, err
	}
	return netnsCookie(netnsPath)
}

// findPodPID scans /proc for the first PID whose cgroup line references
// the pod UID. Returns an error if no live process is found.
func findPodPID(podUID string) (int, error) {
	pids := findPodPIDs([]string{podUID})
	if pid, ok := pids[podUID]; ok {
		return pid, nil
	}
	return 0, fmt.Errorf("no live process found for pod uid %s", podUID)
}

// findPodPIDs scans /proc/*/cgroup once and returns, for each requested
// pod UID that matches a live process, the first such PID (uid -> pid).
// UIDs with no live process are omitted from the result.
//
// A pod UID appears in a process's cgroup path either with dashes
// (cgroupfs driver, e.g. .../pod<uid>/) or with dashes replaced by
// underscores (systemd driver, e.g. .../kubepods-pod<uid_>.slice/); we
// search for either form. Matching every still-unresolved UID against
// each cgroup file in a single pass keeps the scan O(processes) per
// call regardless of how many UIDs are pending, rather than
// O(processes x pods). The scan never runs on the packet path; on busy
// nodes (~thousands of PIDs) it completes well under 100ms.
func findPodPIDs(podUIDs []string) map[string]int {
	// Build the two match forms per UID once, skipping blanks/dupes.
	type forms struct{ dash, underscore string }
	want := make(map[string]forms, len(podUIDs))
	for _, uid := range podUIDs {
		if uid == "" {
			continue
		}
		want[uid] = forms{dash: uid, underscore: strings.ReplaceAll(uid, "-", "_")}
	}
	if len(want) == 0 {
		return nil
	}

	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil
	}
	found := make(map[string]int, len(want))
	for _, e := range entries {
		if len(want) == 0 {
			break // every requested UID resolved
		}
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		cgroupBytes, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "cgroup"))
		if err != nil {
			// Process may have exited between ReadDir and ReadFile.
			continue
		}
		s := string(cgroupBytes)
		for uid, f := range want {
			if strings.Contains(s, f.dash) || strings.Contains(s, f.underscore) {
				found[uid] = pid
				delete(want, uid) // first match wins; stop looking for it
			}
		}
	}
	return found
}

// hostRootPrefix is the prefix used to reach host-filesystem paths from
// inside the calico-node container. The operator bind-mounts the host's
// /proc into calico-node at /host/proc, so /host/proc/1/root is host
// PID-1's root view — the host's mount namespace — regardless of which
// PID namespace calico-node runs in (this does NOT depend on
// hostPID=true). Thus /host/proc/1/root/<host-path> resolves through the
// host's mount namespace.  Overridable for tests.
var hostRootPrefix = "/host/proc/1/root"

// ResolveCookieByPath opens the given netns path and returns the
// kernel-stable netns cookie (the same value SO_NETNS_COOKIE returns
// from a socket inside that namespace, and the same value
// bpf_get_netns_cookie() returns from a BPF program running on a
// socket in that namespace).
//
// The path is the *canonical* host path (symlinks already resolved by
// the CNI plugin at cmdAdd, e.g. /var/run/netns/cni-<uuid> is stored
// as /run/netns/cni-<uuid>), as written into the
// cni.projectcalico.org/podNetns Pod annotation. The file is pinned by
// the container runtime (containerd / cri-o) and only host-root can
// replace it, so it is a trust-anchored input.
//
// Because the netns file lives in the host's mount namespace and Felix
// runs in a container that doesn't bind-mount /var/run/netns, we rewrite
// absolute host paths to go via /host/proc/1/root (the bind-mounted host
// /proc), which resolves through host PID-1's mount namespace. Any
// absolute symlink targets along the way are resolved against the host's
// view with SecureJoin (see hostPath).
//
// Returns an error if the path is empty or can't be opened (pod
// already deleted, race, non-Calico-CNI WEP). Callers should fall back
// to the UID-based /proc scan in that case.
func ResolveCookieByPath(netnsPath string) (uint64, error) {
	if netnsPath == "" {
		return 0, fmt.Errorf("empty netns path")
	}
	return netnsCookie(hostPath(netnsPath))
}

// hostPath rewrites an absolute host path so it resolves through the
// bind-mounted host /proc (hostRootPrefix, /host/proc/1/root in
// production) — i.e. host PID-1's mount namespace — from inside the
// calico-node container. Already-prefixed or non-absolute paths are
// returned unchanged.
//
// Symlinks along the path are resolved against the host's view using
// SecureJoin, so an absolute symlink target (e.g. /var/run -> /run) is
// re-rooted at the host root rather than the container's "/". The
// annotation path is normally already canonical (the CNI plugin runs
// EvalSymlinks at cmdAdd), but SecureJoin keeps this correct for the
// CRI/proc tiers too and matches felix/cri's viaHostRoot. If SecureJoin
// errors (e.g. a broken intermediate symlink) we fall back to the naive
// prefix so the caller still gets a chance to open the path.
func hostPath(netnsPath string) string {
	if !strings.HasPrefix(netnsPath, "/") || strings.HasPrefix(netnsPath, hostRootPrefix+"/") || netnsPath == hostRootPrefix {
		return netnsPath
	}
	resolved, err := securejoin.SecureJoin(hostRootPrefix, netnsPath)
	if err != nil {
		return hostRootPrefix + netnsPath
	}
	return resolved
}

// netnsCookie enters the network namespace referenced by netnsPath and
// returns its kernel-stable cookie. It uses a goroutine pinned to a
// single OS thread so the setns(2) is isolated; the thread is
// discarded on return, avoiding leaks of the swapped netns into the
// rest of the runtime.
func netnsCookie(netnsPath string) (uint64, error) {
	netns, err := ns.GetNS(netnsPath)
	if err != nil {
		return 0, fmt.Errorf("opening netns %s: %w", netnsPath, err)
	}
	defer netns.Close()

	type result struct {
		cookie uint64
		err    error
	}
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		// We intentionally do not UnlockOSThread; the Go runtime
		// will retire this thread when the goroutine returns so any
		// netns swap dies with it.
		ch <- doInNetns(netns)
	}()
	r := <-ch
	return r.cookie, r.err
}

func doInNetns(netns ns.NetNS) (r struct {
	cookie uint64
	err    error
}) {
	if err := netns.Set(); err != nil {
		r.err = fmt.Errorf("setns: %w", err)
		return
	}
	// AF_INET / SOCK_DGRAM is the cheapest socket type that supports
	// SO_NETNS_COOKIE. The socket exists only long enough to read the
	// option.
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		r.err = fmt.Errorf("socket in netns: %w", err)
		return
	}
	defer unix.Close(fd)
	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	if err != nil {
		r.err = fmt.Errorf("getsockopt SO_NETNS_COOKIE: %w", err)
		return
	}
	r.cookie = cookie
	return
}
