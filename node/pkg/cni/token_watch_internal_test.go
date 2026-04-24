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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func TestWriteFileAtomic_ReplacesContentAndLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "calico-kubeconfig")

	if err := os.WriteFile(path, []byte("old-contents"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	newContents := []byte("brand-new-contents")
	if err := writeFileAtomic(path, newContents, 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(newContents) {
		t.Fatalf("content mismatch: got %q, want %q", got, newContents)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != filepath.Base(path) {
			t.Errorf("unexpected leftover file in target dir: %s", e.Name())
		}
	}
}

func TestWriteFileAtomic_PreservesPermissionMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "calico-kubeconfig")

	if err := writeFileAtomic(path, []byte("data"), 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode: got %o, want 0600", got)
	}
}

func TestWriteFileAtomic_NoLeftoverTempOnRewrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "calico-kubeconfig")

	for i := 0; i < 5; i++ {
		if err := writeFileAtomic(path, []byte("rev"+string(rune('a'+i))), 0o600); err != nil {
			t.Fatalf("writeFileAtomic iter %d: %v", i, err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Errorf("temp file leaked: %s", e.Name())
		}
	}
}

// TestTokenRefresher_WakesUpOnTokenFileChange verifies the fsnotify-based
// fast path: when something in the watched directory changes, the refresh
// loop must fire a new UpdateToken long before its scheduled 24h-divided
// timer would otherwise elapse.
func TestTokenRefresher_WakesUpOnTokenFileChange(t *testing.T) {
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

// TestWriteFileAtomic_ConcurrentReaderNeverSeesPartialContent proves the
// property that motivated the switch from os.WriteFile to a rename-based
// atomic write: a concurrent reader — in production, the CNI plugin invoked
// by containerd — must never see an empty, truncated, or partially-written
// file while the refresh loop is rewriting the kubeconfig.
//
// Flakiness notes:
//   - The reader loops until writerDone is closed, so it's not sensitive to
//     CPU scheduling speed — no races with an iteration budget.
//   - Assertions only check "the read bytes equal one of the known valid
//     contents", so they're deterministic regardless of which revision is
//     observed.
//   - The t.TempDir() filesystem on typical Linux CI is ext4/tmpfs where
//     rename(2) is atomic, which is the precondition the code relies on.
func TestWriteFileAtomic_ConcurrentReaderNeverSeesPartialContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "calico-kubeconfig")

	const numRevisions = 100
	revisions := make([][]byte, numRevisions)
	valid := make(map[string]bool, numRevisions)
	for i := 0; i < numRevisions; i++ {
		// Vary the length significantly so a truncate-then-write race would
		// be observable as a prefix of a longer revision or vice versa.
		content := fmt.Sprintf("rev-%03d-%s", i, strings.Repeat("x", (i%16)*64))
		revisions[i] = []byte(content)
		valid[content] = true
	}

	// Seed with the first revision so the reader always has something valid
	// to observe from the very first iteration.
	if err := writeFileAtomic(path, revisions[0], 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	writerDone := make(chan struct{})
	var readErr atomic.Value // holds error
	var reads atomic.Int64

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-writerDone:
				return
			default:
			}
			got, err := os.ReadFile(path)
			if err != nil {
				readErr.Store(fmt.Errorf("read: %w", err))
				return
			}
			if !valid[string(got)] {
				readErr.Store(fmt.Errorf("reader saw unexpected content (len=%d): %q", len(got), got))
				return
			}
			reads.Add(1)
		}
	}()

	for i := 1; i < numRevisions; i++ {
		if err := writeFileAtomic(path, revisions[i], 0o600); err != nil {
			close(writerDone)
			wg.Wait()
			t.Fatalf("write revision %d: %v", i, err)
		}
	}
	close(writerDone)
	wg.Wait()

	if err, ok := readErr.Load().(error); ok {
		t.Fatal(err)
	}
	if reads.Load() == 0 {
		t.Fatal("reader never observed any content — test did not exercise the atomic write path")
	}
}

// TestWriteFileAtomic_ErrorsWhenDirectoryMissing exercises the error path of
// os.CreateTemp when the parent directory does not exist. Fully deterministic.
func TestWriteFileAtomic_ErrorsWhenDirectoryMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist", "calico-kubeconfig")
	err := writeFileAtomic(path, []byte("data"), 0o600)
	if err == nil {
		t.Fatal("expected error when parent directory is missing, got nil")
	}
}

// TestDrainEvents_IsNonBlockingAndDrainsBurst exercises the drainEvents
// helper directly. Fully deterministic: uses a buffered channel, no timers.
func TestDrainEvents_IsNonBlockingAndDrainsBurst(t *testing.T) {
	ch := make(chan fsnotify.Event, 10)
	for i := 0; i < 7; i++ {
		ch <- fsnotify.Event{}
	}

	done := make(chan struct{})
	go func() {
		drainEvents(ch)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("drainEvents did not return on a non-empty channel")
	}

	if got := len(ch); got != 0 {
		t.Errorf("expected channel drained, still has %d events", got)
	}

	// Calling drainEvents on an already-empty channel must also return
	// promptly without blocking.
	done2 := make(chan struct{})
	go func() {
		drainEvents(ch)
		close(done2)
	}()
	select {
	case <-done2:
	case <-time.After(2 * time.Second):
		t.Fatal("drainEvents did not return on an empty channel")
	}
}

// TestTokenRefresher_DegradesGracefullyWhenWatcherChannelCloses covers the
// "!ok" branch in Run's select: if the fsnotify watcher dies mid-run and its
// events channel closes, the refresh loop must keep operating on its timer
// rather than spinning on the closed channel.
//
// Flakiness notes:
//   - The watcher factory is injected and returns an already-closed channel,
//     so the close signal is delivered deterministically on the very first
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
	// Return a pre-closed channel: the first select iteration will see !ok
	// on tokenRotated and must not latch into a hot loop.
	closedEvents := make(chan fsnotify.Event)
	close(closedEvents)
	tr.watcherFactory = func() (<-chan fsnotify.Event, func()) {
		return closedEvents, func() {}
	}

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
