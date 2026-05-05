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

package cni

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	goruntime "runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// Constants and helpers below mirror upstream kubelet's atomic projected
// volume writer. The behaviour we want to verify is whether fsnotify on the
// parent directory observes the events that real kubelet generates.
//
// Source: kubernetes/kubernetes pkg/volume/util/atomic_writer.go
//
//	tag: v1.35.4 (the version pinned in this repo's go.mod)
//	SHA: ee674200d315db92e2ef8274bad32731eefe1104
//	url: https://github.com/kubernetes/kubernetes/blob/v1.35.4/pkg/volume/util/atomic_writer.go
const (
	kubeletDataDirName    = "..data"     // matches atomic_writer.go const
	kubeletNewDataDirName = "..data_tmp" // matches atomic_writer.go const
)

// TestTokenRefresher_WakesUpOnTokenFileChange verifies the fsnotify-based
// fast path: when something in the watched directory changes, the refresh
// loop must fire a new UpdateToken long before its scheduled 24h-divided
// timer would otherwise elapse.
func TestTokenRefresher_WakesUpOnTokenFileChange(t *testing.T) {
	skipIfFsnotifyFastPathDisabled(t)
	tokenDir := t.TempDir()
	tokenPath := filepath.Join(tokenDir, "token")

	var callCount int32
	fakeClient := fake.NewSimpleClientset()
	fakeClient.PrependReactor("create", "serviceaccounts", func(action ktesting.Action) (bool, runtime.Object, error) {
		createAction, ok := action.(ktesting.CreateAction)
		if !ok || createAction.GetSubresource() != "token" {
			return false, nil, nil
		}
		atomic.AddInt32(&callCount, 1)
		return true, &authv1.TokenRequest{
			Status: authv1.TokenRequestStatus{
				Token:               "fake-token",
				ExpirationTimestamp: metav1.NewTime(time.Now().Add(24 * time.Hour)),
			},
		}, nil
	})

	tr := NewTokenRefresher(fakeClient, "kube-system", "calico-cni-plugin")
	tr.tokenFilePath = tokenPath

	// Run() sends each successful token update on an unbuffered channel, so
	// we need an active receiver for the refresh loop to make forward
	// progress between iterations. The drain goroutine exits on stopDrain
	// so the test doesn't leak.
	stopDrain := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-tr.TokenChan():
			case <-stopDrain:
				return
			}
		}
	}()
	defer func() {
		tr.Stop()
		close(stopDrain)
		wg.Wait()
	}()

	go tr.Run()

	// Wait for the initial refresh to complete so we know the loop has entered
	// its long sleep (the default cadence for a 24h token is ~6-12h).
	if err := waitForCalls(&callCount, 1, 2*time.Second); err != nil {
		t.Fatalf("initial UpdateToken did not fire: %v", err)
	}

	// Simulate kubelet projecting a new token into the watched directory.
	if err := os.WriteFile(tokenPath, []byte("new-token-bytes"), 0o600); err != nil {
		t.Fatalf("touch token file: %v", err)
	}

	// The fsnotify wake-up should trigger a second UpdateToken within seconds,
	// not hours. If this times out the fast path is broken.
	if err := waitForCalls(&callCount, 2, 3*time.Second); err != nil {
		t.Fatalf("token rotation did not wake up refresh loop: %v", err)
	}
}

// TestTokenRefresher_FallsBackWhenWatcherSetupFails confirms that Run still
// produces tokens on the normal timer path when the token file directory
// doesn't exist (which makes the fsnotify Add call fail).
func TestTokenRefresher_FallsBackWhenWatcherSetupFails(t *testing.T) {
	var callCount int32
	fakeClient := fake.NewSimpleClientset()
	fakeClient.PrependReactor("create", "serviceaccounts", func(action ktesting.Action) (bool, runtime.Object, error) {
		createAction, ok := action.(ktesting.CreateAction)
		if !ok || createAction.GetSubresource() != "token" {
			return false, nil, nil
		}
		atomic.AddInt32(&callCount, 1)
		return true, &authv1.TokenRequest{
			Status: authv1.TokenRequestStatus{
				Token:               "fake-token",
				ExpirationTimestamp: metav1.NewTime(time.Now().Add(24 * time.Hour)),
			},
		}, nil
	})

	tr := NewTokenRefresher(fakeClient, "kube-system", "calico-cni-plugin")
	tr.tokenFilePath = filepath.Join(t.TempDir(), "does-not-exist", "token")

	stopDrain := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-tr.TokenChan():
			case <-stopDrain:
				return
			}
		}
	}()
	defer func() {
		tr.Stop()
		close(stopDrain)
		wg.Wait()
	}()

	go tr.Run()

	if err := waitForCalls(&callCount, 1, 2*time.Second); err != nil {
		t.Fatalf("initial UpdateToken did not fire in fallback mode: %v", err)
	}
}

// TestTokenRefresher_DegradesGracefullyWhenWatcherChannelCloses covers the
// "!ok" branch in Run's select: if the fsnotify watcher dies mid-run and its
// events channel closes, the refresh loop must keep operating on its timer
// rather than spinning on the closed channel.
//
// Flakiness notes:
//   - The injected notifier returns an already-closed channel, so the
//     close signal is delivered deterministically on the very first
//     select iteration after the first token is delivered.
//   - Uses a short minTokenRetryDuration so subsequent refreshes happen
//     within the test timeout.
func TestTokenRefresher_DegradesGracefullyWhenWatcherChannelCloses(t *testing.T) {
	var callCount int32
	fakeClient := fake.NewSimpleClientset()
	fakeClient.PrependReactor("create", "serviceaccounts", func(action ktesting.Action) (bool, runtime.Object, error) {
		createAction, ok := action.(ktesting.CreateAction)
		if !ok || createAction.GetSubresource() != "token" {
			return false, nil, nil
		}
		atomic.AddInt32(&callCount, 1)
		// Very short expiry so getSleepTime's clamp fires and the loop
		// retries quickly via its timer after the watcher channel closes.
		return true, &authv1.TokenRequest{
			Status: authv1.TokenRequestStatus{
				Token:               "fake-token",
				ExpirationTimestamp: metav1.NewTime(time.Now().Add(time.Second)),
			},
		}, nil
	})

	tr := NewTokenRefresherWithCustomTiming(fakeClient, "kube-system", "calico-cni-plugin", 600, 50*time.Millisecond, 4)
	// Inject a notifier whose Events channel is already closed: the first
	// select iteration will see !ok and must not latch into a hot loop.
	closed := make(chan struct{})
	close(closed)
	tr.notifier = &fakeFileNotifier{events: closed}

	stopDrain := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-tr.TokenChan():
			case <-stopDrain:
				return
			}
		}
	}()
	defer func() {
		tr.Stop()
		close(stopDrain)
		wg.Wait()
	}()

	go tr.Run()

	// At least two UpdateToken calls prove the timer continued to fire
	// after the watcher's channel closed.
	if err := waitForCalls(&callCount, 2, 3*time.Second); err != nil {
		t.Fatalf("refresh loop did not continue on timer after watcher closed: %v", err)
	}
}

// TestTokenRefresher_RecoversAfterTransientUpdateTokenError checks the
// existing error path: the first UpdateToken call fails, the loop retries
// quickly (via minTokenRetryDuration + jitter) and then delivers a token on
// success.
//
// Flakiness notes:
//   - Uses minTokenRetryDuration = 50ms so recovery is well under the
//     3-second deadline on any machine.
//   - waitForCalls polls every 20ms so there's no busy-wait race.
func TestTokenRefresher_RecoversAfterTransientUpdateTokenError(t *testing.T) {
	var callCount int32
	var tokensReceived int32
	fakeClient := fake.NewSimpleClientset()
	fakeClient.PrependReactor("create", "serviceaccounts", func(action ktesting.Action) (bool, runtime.Object, error) {
		createAction, ok := action.(ktesting.CreateAction)
		if !ok || createAction.GetSubresource() != "token" {
			return false, nil, nil
		}
		n := atomic.AddInt32(&callCount, 1)
		if n == 1 {
			return true, nil, errors.New("transient error from fake api server")
		}
		return true, &authv1.TokenRequest{
			Status: authv1.TokenRequestStatus{
				Token:               "fake-token",
				ExpirationTimestamp: metav1.NewTime(time.Now().Add(24 * time.Hour)),
			},
		}, nil
	})

	tr := NewTokenRefresherWithCustomTiming(fakeClient, "kube-system", "calico-cni-plugin", 86400, 50*time.Millisecond, 4)
	tr.tokenFilePath = filepath.Join(t.TempDir(), "token")

	stopDrain := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-tr.TokenChan():
				atomic.AddInt32(&tokensReceived, 1)
			case <-stopDrain:
				return
			}
		}
	}()
	defer func() {
		tr.Stop()
		close(stopDrain)
		wg.Wait()
	}()

	go tr.Run()

	if err := waitForCalls(&tokensReceived, 1, 3*time.Second); err != nil {
		t.Fatalf("no token delivered after transient error: %v", err)
	}
	if got := atomic.LoadInt32(&callCount); got < 2 {
		t.Fatalf("expected >= 2 UpdateToken calls (1 failed + 1 successful), got %d", got)
	}
}

// skipIfNotKubeletPosix skips tests that depend on the Linux/POSIX branch
// of kubelet's atomic-writer (os.Rename over an existing symlink, plus
// unprivileged os.Symlink). On Windows kubelet uses a Remove+Symlink+Remove
// sequence instead of Rename, and os.Symlink needs Administrator there.
// macOS works mechanically but its projected-volume layout differs.
func skipIfNotKubeletPosix(t *testing.T) {
	t.Helper()
	if goruntime.GOOS != "linux" {
		t.Skipf("kubelet atomic-writer simulation is Linux-only (GOOS=%s)", goruntime.GOOS)
	}
}

// skipIfFsnotifyFastPathDisabled mirrors the production guard in
// NewFsnotifyFileNotifier, which returns a no-op notifier on Windows.
// Tests that assert the fast-path wake-up cannot meaningfully run there.
func skipIfFsnotifyFastPathDisabled(t *testing.T) {
	t.Helper()
	if goruntime.GOOS == "windows" {
		t.Skipf("fsnotify CNI token fast path is disabled on Windows; nothing to wake up (GOOS=%s)", goruntime.GOOS)
	}
}

// kubeletNewTimestampDir mirrors AtomicWriter.newTimestampDir from
// kubernetes/kubernetes v1.35.4 pkg/volume/util/atomic_writer.go (line ~398):
// uses os.MkdirTemp under the target dir with the prefix
// time.Now().UTC().Format("..2006_01_02_15_04_05."), then chmods to 0755.
func kubeletNewTimestampDir(t *testing.T, targetDir string) string {
	t.Helper()
	tsDir, err := os.MkdirTemp(targetDir, time.Now().UTC().Format("..2006_01_02_15_04_05."))
	if err != nil {
		t.Fatalf("MkdirTemp in %s: %v", targetDir, err)
	}
	if err := os.Chmod(tsDir, 0o755); err != nil {
		t.Fatalf("chmod tsDir: %v", err)
	}
	return tsDir
}

// kubeletAtomicSetUpInitial mirrors what kubelet's AtomicWriter produces on
// the very first projection of a volume: a timestamped data directory holding
// the real files, a `..data` symlink pointing at it, and user-visible
// symlinks (token / ca.crt / namespace) that resolve through `..data`.
// Returns the path of the timestamped data directory.
func kubeletAtomicSetUpInitial(t *testing.T, dir string, files map[string]string) string {
	t.Helper()
	tsDir := kubeletNewTimestampDir(t, dir)
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(tsDir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write payload %s: %v", name, err)
		}
	}
	if err := os.Symlink(filepath.Base(tsDir), filepath.Join(dir, kubeletDataDirName)); err != nil {
		t.Fatalf("symlink %s: %v", kubeletDataDirName, err)
	}
	for name := range files {
		if err := os.Symlink(filepath.Join(kubeletDataDirName, name), filepath.Join(dir, name)); err != nil {
			t.Fatalf("symlink user-visible %s: %v", name, err)
		}
	}
	return tsDir
}

// kubeletAtomicRotate is a faithful port of the file-system operations
// performed by AtomicWriter.Write in kubernetes/kubernetes v1.35.4
// pkg/volume/util/atomic_writer.go (lines 139–267) when shouldWrite=true,
// reordered to skip steps that don't touch the watched directory:
//
//	(5)  os.MkdirTemp(targetDir, "..<timestamp>.")  — new ts data dir
//	(6)  os.WriteFile per payload key into ts dir
//	(8)  os.Symlink(tsDirName, ..data_tmp)
//	(9)  os.Rename(..data_tmp, ..data)              — atomic swap (Linux path)
//	(12) os.RemoveAll(oldTsDir)                     — clean up previous gen
//
// Skipped: (1) validatePayload, (2) Readlink ..data, (3-4) compare with old
// payload, (7) optional setPerms, (10) createUserVisibleFiles (no-op when
// symlinks already exist — see issue #121472), (11) removeUserVisiblePaths
// (only fires when payload key set changes). None of those produce events
// that affect the watcher on the parent directory in the steady-state
// rotation case we care about.
//
// The Windows branch of (9) (Remove + re-Symlink instead of Rename) is not
// modelled here — it would only matter on Windows and the projected volume
// layout differs there anyway.
func kubeletAtomicRotate(t *testing.T, dir, oldTsDir string, files map[string]string) string {
	t.Helper()
	newTsDir := kubeletNewTimestampDir(t, dir)
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(newTsDir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write new payload %s: %v", name, err)
		}
	}
	newDataDirPath := filepath.Join(dir, kubeletNewDataDirName)
	if err := os.Symlink(filepath.Base(newTsDir), newDataDirPath); err != nil {
		t.Fatalf("symlink %s -> %s: %v", kubeletNewDataDirName, filepath.Base(newTsDir), err)
	}
	if err := os.Rename(newDataDirPath, filepath.Join(dir, kubeletDataDirName)); err != nil {
		t.Fatalf("rename %s -> %s: %v", kubeletNewDataDirName, kubeletDataDirName, err)
	}
	if oldTsDir != "" {
		if err := os.RemoveAll(oldTsDir); err != nil {
			t.Fatalf("remove old ts dir %s: %v", oldTsDir, err)
		}
	}
	return newTsDir
}

// TestFsnotifyDetectsKubeletAtomicWriterRotation verifies that fsnotify on
// the parent directory actually delivers events for kubelet's atomic-writer
// rotation sequence (new timestamped dir, symlink rename of `..data`, old
// dir removal). Without those events the fast path would never fire on a
// real rotation since the user-visible files (token, ca.crt, namespace)
// are themselves never modified.
func TestFsnotifyDetectsKubeletAtomicWriterRotation(t *testing.T) {
	skipIfNotKubeletPosix(t)
	dir := t.TempDir()
	files := map[string]string{
		"token":     "initial-token",
		"ca.crt":    "ca-cert-pem",
		"namespace": "kube-system",
	}
	oldDataDir := kubeletAtomicSetUpInitial(t, dir, files)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatalf("new watcher: %v", err)
	}
	defer func() { _ = watcher.Close() }()
	if err := watcher.Add(dir); err != nil {
		t.Fatalf("add watch: %v", err)
	}

	// Drain anything that may have queued before we issue the rotation.
	for draining := true; draining; {
		select {
		case <-watcher.Events:
		default:
			draining = false
		}
	}

	rotated := map[string]string{
		"token":     "rotated-token",
		"ca.crt":    "ca-cert-pem",
		"namespace": "kube-system",
	}
	kubeletAtomicRotate(t, dir, oldDataDir, rotated)

	// Collect every event for a short window and log what the kernel
	// actually delivered, so failures here come with actionable diagnostics.
	deadline := time.After(2 * time.Second)
	var got []fsnotify.Event
collect:
	for {
		select {
		case ev, ok := <-watcher.Events:
			if !ok {
				break collect
			}
			got = append(got, ev)
		case err := <-watcher.Errors:
			t.Logf("watcher error: %v", err)
		case <-deadline:
			break collect
		}
	}

	if len(got) == 0 {
		t.Fatalf("fsnotify on the parent directory delivered no events for kubelet's atomic-writer rotation; " +
			"the fast path in TokenRefresher.Run will not fire on real token rotations.")
	}
	t.Logf("fsnotify delivered %d events for the kubelet atomic-writer rotation:", len(got))
	for _, ev := range got {
		t.Logf("  %s  %s", ev.Op, ev.Name)
	}
}

// TestTokenRefresher_WakesUpOnAtomicWriterRotation is the end-to-end
// counterpart: drive Run against a directory updated with the kubelet
// atomic-writer pattern and assert that UpdateToken fires soon after the
// rotation, which is the user-visible behaviour we promise.
func TestTokenRefresher_WakesUpOnAtomicWriterRotation(t *testing.T) {
	skipIfNotKubeletPosix(t)
	dir := t.TempDir()
	files := map[string]string{
		"token":     "initial-token",
		"ca.crt":    "ca-cert-pem",
		"namespace": "kube-system",
	}
	oldDataDir := kubeletAtomicSetUpInitial(t, dir, files)

	var callCount int32
	fakeClient := fake.NewSimpleClientset()
	fakeClient.PrependReactor("create", "serviceaccounts", func(action ktesting.Action) (bool, runtime.Object, error) {
		createAction, ok := action.(ktesting.CreateAction)
		if !ok || createAction.GetSubresource() != "token" {
			return false, nil, nil
		}
		atomic.AddInt32(&callCount, 1)
		return true, &authv1.TokenRequest{
			Status: authv1.TokenRequestStatus{
				Token:               "fake-token",
				ExpirationTimestamp: metav1.NewTime(time.Now().Add(24 * time.Hour)),
			},
		}, nil
	})

	tr := NewTokenRefresher(fakeClient, "kube-system", "calico-cni-plugin")
	tr.tokenFilePath = filepath.Join(dir, "token")

	stopDrain := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-tr.TokenChan():
			case <-stopDrain:
				return
			}
		}
	}()
	defer func() {
		tr.Stop()
		close(stopDrain)
		wg.Wait()
	}()

	go tr.Run()

	if err := waitForCalls(&callCount, 1, 2*time.Second); err != nil {
		t.Fatalf("initial UpdateToken did not fire: %v", err)
	}

	// The refresh loop is now sleeping in its 6-12h timer. Trigger a kubelet-
	// style rotation. If the watcher delivers events for this pattern, Run()
	// will wake up and call UpdateToken a second time within seconds.
	rotated := map[string]string{
		"token":     "rotated-token",
		"ca.crt":    "ca-cert-pem",
		"namespace": "kube-system",
	}
	kubeletAtomicRotate(t, dir, oldDataDir, rotated)

	if err := waitForCalls(&callCount, 2, 3*time.Second); err != nil {
		t.Fatalf("kubelet atomic-writer rotation did not wake up the refresh loop: %v "+
			"(see TestFsnotifyDetectsKubeletAtomicWriterRotation for the lower-level "+
			"diagnostic of what events the kernel delivered).", err)
	}
}

// TestTokenRefresher_HandlesBurstRotations covers the apiserver-burst
// concern: kubelet's atomic-writer produces ~5 fsnotify events per rotation
// (CREATE new ts dir, CREATE ..data_tmp, RENAME, CREATE ..data, REMOVE old
// ts dir). Without coalescing, each event would map to its own CreateToken
// call, multiplying the burst at kube-apiserver by ~5N when many nodes
// rotate at once (e.g. signing-key rotation). The notifier coalesces a
// burst into a single wake-up, so a tight sequence of N rotations should
// produce one extra UpdateToken, plus a small slack for the rare case
// where the loop re-enters select between two rotations.
func TestTokenRefresher_HandlesBurstRotations(t *testing.T) {
	skipIfNotKubeletPosix(t)
	dir := t.TempDir()
	files := map[string]string{"token": "v0", "ca.crt": "ca-cert-pem", "namespace": "kube-system"}
	currentTs := kubeletAtomicSetUpInitial(t, dir, files)

	var callCount int32
	fakeClient := fake.NewSimpleClientset()
	fakeClient.PrependReactor("create", "serviceaccounts", func(action ktesting.Action) (bool, runtime.Object, error) {
		createAction, ok := action.(ktesting.CreateAction)
		if !ok || createAction.GetSubresource() != "token" {
			return false, nil, nil
		}
		atomic.AddInt32(&callCount, 1)
		return true, &authv1.TokenRequest{
			Status: authv1.TokenRequestStatus{
				Token:               "fake-token",
				ExpirationTimestamp: metav1.NewTime(time.Now().Add(24 * time.Hour)),
			},
		}, nil
	})

	tr := NewTokenRefresher(fakeClient, "kube-system", "calico-cni-plugin")
	tr.tokenFilePath = filepath.Join(dir, "token")

	stopDrain := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-tr.TokenChan():
			case <-stopDrain:
				return
			}
		}
	}()
	defer func() {
		tr.Stop()
		close(stopDrain)
		wg.Wait()
	}()

	go tr.Run()

	if err := waitForCalls(&callCount, 1, 2*time.Second); err != nil {
		t.Fatalf("initial UpdateToken did not fire: %v", err)
	}

	const numRotations = 5
	for i := 0; i < numRotations; i++ {
		currentTs = kubeletAtomicRotate(t, dir, currentTs, files)
	}

	// Wait long enough for: every event to surface from fsnotify, the
	// coalesce window (50 ms) to elapse, and UpdateToken to run.
	time.Sleep(500 * time.Millisecond)

	final := atomic.LoadInt32(&callCount)
	if final < 2 {
		t.Fatalf("expected at least 2 UpdateToken calls (1 initial + >=1 wake-up), got %d", final)
	}
	// Upper bound: 1 initial + a small number of coalesced wake-ups. With
	// the rotations happening in a tight Go loop they should all fall inside
	// one coalesce window. The bound is well below the un-coalesced worst
	// case (1 + numRotations * ~5, around 26), so a regression in the
	// coalesce path will fail this test rather than slip through.
	const maxWakeups = 3
	upperBound := int32(1 + maxWakeups)
	if final > upperBound {
		t.Fatalf("UpdateToken called more than coalesced expectation: got %d, cap %d "+
			"(coalesce window may no longer be absorbing the kubelet rotation burst).",
			final, upperBound)
	}
	t.Logf("burst of %d rotations triggered %d UpdateToken calls (initial+wake-ups)", numRotations, final)
}

// TestTokenRefresher_NoGoroutineLeakOnRunStopCycle guards against goroutine
// leaks in the watcher / errors-drainer / Run() pipeline. Repeatedly start
// and stop a refresher, then assert the global goroutine count returns to
// its baseline. A leak in the cleanup path would show up as monotonic growth.
func TestTokenRefresher_NoGoroutineLeakOnRunStopCycle(t *testing.T) {
	// Settle and snapshot the baseline.
	goruntime.GC()
	time.Sleep(100 * time.Millisecond)
	baseline := goruntime.NumGoroutine()

	const cycles = 30
	for i := 0; i < cycles; i++ {
		dir := t.TempDir()
		// fsnotify needs the directory to exist for watcher.Add to succeed,
		// otherwise we exercise the timer-only fallback path which is a
		// different code path (and uncovered by this test).
		if err := os.WriteFile(filepath.Join(dir, "token"), []byte("x"), 0o600); err != nil {
			t.Fatalf("seed token: %v", err)
		}

		fakeClient := fake.NewSimpleClientset()
		fakeClient.PrependReactor("create", "serviceaccounts", func(action ktesting.Action) (bool, runtime.Object, error) {
			createAction, ok := action.(ktesting.CreateAction)
			if !ok || createAction.GetSubresource() != "token" {
				return false, nil, nil
			}
			return true, &authv1.TokenRequest{
				Status: authv1.TokenRequestStatus{
					Token:               "fake-token",
					ExpirationTimestamp: metav1.NewTime(time.Now().Add(24 * time.Hour)),
				},
			}, nil
		})

		tr := NewTokenRefresher(fakeClient, "kube-system", "calico-cni-plugin")
		tr.tokenFilePath = filepath.Join(dir, "token")

		runDone := make(chan struct{})
		go func() {
			defer close(runDone)
			tr.Run()
		}()

		// Drain at least one token to confirm Run got past startup.
		select {
		case <-tr.TokenChan():
		case <-time.After(2 * time.Second):
			t.Fatalf("cycle %d: Run did not deliver any token", i)
		}

		tr.Stop()
		select {
		case <-runDone:
		case <-time.After(2 * time.Second):
			t.Fatalf("cycle %d: Run did not return after Stop", i)
		}
	}

	// Let goroutines wind down (watcher Close + errors-drainer exit).
	goruntime.GC()
	time.Sleep(300 * time.Millisecond)
	goruntime.Gosched()
	final := goruntime.NumGoroutine()

	// Allow some slack for runtime / GC goroutines that may not be exactly
	// stable across invocations.
	const slack = 5
	if final > baseline+slack {
		t.Fatalf("goroutine leak: baseline=%d final=%d (after %d Run/Stop cycles, slack=%d)",
			baseline, final, cycles, slack)
	}
}

// TestTokenRefresher_StopIsIdempotent confirms repeated Stop calls are safe.
// Calling Stop more than once is plausible (e.g. one goroutine on ctx.Done
// and another via defer during teardown), and a naive close(stopChan) would
// panic with "close of closed channel".
func TestTokenRefresher_StopIsIdempotent(t *testing.T) {
	tr := NewTokenRefresher(fake.NewSimpleClientset(), "kube-system", "calico-cni-plugin")
	tr.Stop()
	tr.Stop() // must not panic
	tr.Stop()
}

func waitForCalls(counter *int32, want int32, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(counter) >= want {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for calls: want=%d got=%d", want, atomic.LoadInt32(counter))
}

// fakeFileNotifier is a test double for FileNotifier. The events field is
// returned verbatim from Events(), so tests can pass nil (inert), an
// already-closed channel (immediate degrade), or a sender they control.
type fakeFileNotifier struct {
	events chan struct{}
}

func (f *fakeFileNotifier) Events() <-chan struct{} { return f.events }
func (f *fakeFileNotifier) Close()                  {}

// makeTestJWT builds a JWT-shaped string with the given claims JSON. JWT
// segments use base64url *without* padding, matching what real Kubernetes
// service-account tokens look like and what parseTokenUpdate expects.
func makeTestJWT(claimsJSON string) []byte {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	claims := base64.RawURLEncoding.EncodeToString([]byte(claimsJSON))
	sig := base64.RawURLEncoding.EncodeToString([]byte("sig"))
	return []byte(header + "." + claims + "." + sig)
}

// TestParseTokenUpdate_RejectsMalformedExp verifies that a token whose "exp"
// claim is not a number returns an error rather than panicking. A panic in
// this path would tear down the entire calico-node process on any malformed
// token, which is unacceptable for a node-agent that runs everywhere.
func TestParseTokenUpdate_RejectsMalformedExp(t *testing.T) {
	cases := []struct {
		name   string
		claims string
	}{
		{"exp is string", `{"exp":"not-a-number"}`},
		{"exp is bool", `{"exp":true}`},
		{"exp is null", `{"exp":null}`},
		{"exp is object", `{"exp":{"nested":1}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseTokenUpdate(makeTestJWT(tc.claims))
			if err == nil {
				t.Fatalf("expected error for claims %q, got nil", tc.claims)
			}
		})
	}
}

// TestParseTokenUpdate_RejectsMissingExp confirms that a token with no
// "exp" claim at all also returns an error rather than panicking.
func TestParseTokenUpdate_RejectsMissingExp(t *testing.T) {
	_, err := parseTokenUpdate(makeTestJWT(`{"sub":"system:serviceaccount:kube-system:calico-cni-plugin"}`))
	if err == nil {
		t.Fatal("expected error when 'exp' is missing, got nil")
	}
}

// TestParseTokenUpdate_AcceptsWellFormedExp is the happy-path counterpart
// to the rejection tests: a numeric "exp" claim yields a usable TokenUpdate.
func TestParseTokenUpdate_AcceptsWellFormedExp(t *testing.T) {
	const want int64 = 4102444800 // 2100-01-01T00:00:00Z
	tu, err := parseTokenUpdate(makeTestJWT(fmt.Sprintf(`{"exp":%d}`, want)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := tu.ExpirationTime.Unix(); got != want {
		t.Fatalf("ExpirationTime=%d, want %d", got, want)
	}
}
