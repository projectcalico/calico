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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
