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

package binder

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPollStopsWhileBlockedSendingAddedEvent(t *testing.T) {
	dir := t.TempDir()
	credDir := filepath.Join(dir, CredentialsSubdir)
	if err := os.Mkdir(credDir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, uid := range []string{"workload-1", "workload-2"} {
		if err := os.WriteFile(filepath.Join(credDir, uid+CredentialsExtension), []byte("{}"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	p := &pollWatcher{path: dir}
	events := make(chan workloadEvent)
	stop := make(chan bool)
	done := make(chan struct{})
	go func() {
		p.poll(events, stop)
		close(done)
	}()

	select {
	case <-events:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("poll did not send initial workload event")
	}

	close(stop)

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("poll did not stop while blocked sending workload event")
	}
}
