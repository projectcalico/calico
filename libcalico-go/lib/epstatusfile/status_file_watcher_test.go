// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package epstatusfile

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

type fsnotifyError struct {
	remainingErrors int
	sync.Mutex
}

func (e *fsnotifyError) ShouldError() bool {
	e.Lock()
	defer func() {
		if e.remainingErrors > 0 {
			e.remainingErrors--
			log.Debugf("fsnotifyError has %d failures remaining", e.remainingErrors)
		}
		e.Unlock()
	}()

	return e.remainingErrors != 0
}

// ErrorNTimes instructs ShouldError to return false the next N times.
// Set to -1 to return false forever, or 0 to return true forever.
func (e *fsnotifyError) ErrorNTimes(n int) {
	e.Lock()
	defer e.Unlock()

	e.remainingErrors = n
}

// A shim for generating artificial errors during fsnotify setup.
func (e *fsnotifyError) newFsnotifyWatcherShim() (*fsnotify.Watcher, error) {
	if e.ShouldError() {
		return nil, fmt.Errorf("simulating an error on initializing fsnotify")
	}
	return fsnotify.NewWatcher()
}

type eventRecorder struct {
	fileNameToEvents map[string][]string
	inSyncEvents     []bool
	sync.Mutex
}

func newEventRecorder() *eventRecorder {
	return &eventRecorder{
		fileNameToEvents: make(map[string][]string),
	}
}

func (e *eventRecorder) OnFileEvent(fileName string, event string) {
	e.Lock()
	defer e.Unlock()
	log.WithField("file", fileName).Debugf("file %s", event)

	// Initialize the slice if it doesn't exist
	if _, exists := e.fileNameToEvents[fileName]; !exists {
		e.fileNameToEvents[fileName] = []string{}
	}

	// Append the event
	e.fileNameToEvents[fileName] = append(e.fileNameToEvents[fileName], event)

	log.Debugf("%v", e.fileNameToEvents)
}

func (e *eventRecorder) OnFileCreate(fileName string) {
	e.OnFileEvent(fileName, "create")
}

func (e *eventRecorder) OnFileUpdate(fileName string) {
	e.OnFileEvent(fileName, "update")
}

func (e *eventRecorder) OnFileDeletion(fileName string) {
	e.OnFileEvent(fileName, "delete")
}

func (e *eventRecorder) OnInSync(s bool) {
	e.Lock()
	defer e.Unlock()
	e.inSyncEvents = append(e.inSyncEvents, s)
}

func (e *eventRecorder) Events() map[string][]string {
	e.Lock()
	defer e.Unlock()
	return maps.Clone(e.fileNameToEvents)
}

func (e *eventRecorder) InSyncEvents() []bool {
	e.Lock()
	defer e.Unlock()
	return e.inSyncEvents
}

func clearDir(dirPath string) {
	entries, err := os.ReadDir(dirPath)
	Expect(err).ShouldNot(HaveOccurred())

	for _, entry := range entries {
		err := os.Remove(dirPath + "/" + entry.Name()) // Remove each file
		Expect(err).ShouldNot(HaveOccurred())
	}

	log.Infof("Directory %s cleared successfully!", dirPath)
}

var _ = Describe("Workload endpoint status file watcher test", func() {
	var w *FileWatcher
	var r *eventRecorder
	var fsnotifyErr *fsnotifyError
	var fsnotifyActivity *activityReporter

	tmpPath := "/go/src/github.com/projectcalico/calico/ut-tmp-dir"
	statusDir := tmpPath + "/endpoint-status"
	err := os.MkdirAll(statusDir, 0755)
	Expect(err).ShouldNot(HaveOccurred())

	writer := NewEndpointStatusFileWriter(tmpPath)

	haveEvents := func(filePath string, expected []string) bool {
		// The kernel can fire many WRITE events for a single logical write, if the data is truncated.
		// So, it's error-prone to check our sequence of logical events is directly-equivalent to the actual.
		// Instead, we check that the logical sequence exists within the actual sequence, which should account for duplicates.
		events, exist := r.Events()[filePath]
		if !exist {
			return false
		}

		window := len(expected)
		for i := 0; i < len(events)-(window-1); i++ {
			log.Infof("searching file events window %v, matching %v", events[i:i+window], expected)
			if slices.Equal(events[i:i+window], expected) {
				return true
			}
		}
		return false
	}

	lastInSync := func() bool {
		e := r.InSyncEvents()
		if len(e) == 0 {
			return false
		}
		return e[len(e)-1]
	}

	BeforeEach(func() {
		clearDir(statusDir)
		fsnotifyActivity = new(activityReporter)
		fsnotifyErr = new(fsnotifyError)
		w = NewFileWatcherWithShim(statusDir, 10*time.Second, fsnotifyErr.newFsnotifyWatcherShim, fsnotifyActivity)
		r = newEventRecorder()
		w.SetCallbacks(Callbacks{
			OnFileCreation: r.OnFileCreate,
			OnFileUpdate:   r.OnFileUpdate,
			OnFileDeletion: r.OnFileDeletion,
			OnInSync:       r.OnInSync,
		})
	})

	It("should receive events on files already been created", func() {
		err = writer.WriteStatusFile("pod1", "name: pod1")
		Expect(err).ShouldNot(HaveOccurred())

		w.Start()
		defer w.Stop()
		Eventually(fsnotifyActivity.Poll, "3s").Should(BeTrue())

		filePath := filepath.Join(statusDir, "pod1")
		Eventually(haveEvents, "5s", "1s").WithArguments(filePath, []string{"create"}).Should(BeTrue())
		Eventually(r.InSyncEvents).ShouldNot(BeEmpty())

		Eventually(lastInSync).Should(BeTrue())
	})

	It("should receive events on files been updated", func() {
		err = writer.WriteStatusFile("pod1", "name: pod1")
		Expect(err).ShouldNot(HaveOccurred())

		w.Start()
		defer w.Stop()
		Eventually(fsnotifyActivity.Poll, "3s").Should(BeTrue())

		filePath := filepath.Join(statusDir, "pod1")
		Eventually(haveEvents, "5s", "1s").WithArguments(filePath, []string{"create"}).Should(BeTrue())
		Eventually(lastInSync).Should(BeTrue())

		err = writer.WriteStatusFile("pod1", "name: pod1, status: active")
		Expect(err).ShouldNot(HaveOccurred())

		Eventually(haveEvents, "5s", "1s").WithArguments(filePath, []string{"create", "update"}).Should(BeTrue())
		Eventually(lastInSync).Should(BeTrue())
	})

	It("should receive events on files been deleted", func() {
		err = writer.WriteStatusFile("pod1", "name: pod1")
		Expect(err).ShouldNot(HaveOccurred())

		w.Start()
		defer w.Stop()
		Eventually(fsnotifyActivity.Poll, "3s").Should(BeTrue())

		filePath := filepath.Join(statusDir, "pod1")
		Eventually(haveEvents, "5s", "1s").WithArguments(filePath, []string{"create"}).Should(BeTrue())
		Eventually(lastInSync).Should(BeTrue())

		err = writer.DeleteStatusFile("pod1")
		Expect(err).ShouldNot(HaveOccurred())

		Eventually(haveEvents, "5s", "1s").WithArguments(filePath, []string{"create", "delete"}).Should(BeTrue())
		Eventually(lastInSync).Should(BeTrue())

	})

	It("should receive events when fsnotify fails", func() {
		w.Start()
		defer w.Stop()
		Eventually(fsnotifyActivity.Poll, "3s").Should(BeTrue())

		err = writer.WriteStatusFile("pod1", "name: pod1")
		Expect(err).ShouldNot(HaveOccurred())

		filePath := filepath.Join(statusDir, "pod1")
		Eventually(haveEvents, "5s", "1s").WithArguments(filePath, []string{"create", "update"}).Should(BeTrue())
		Eventually(lastInSync).Should(BeTrue())

		// Simulate an error on new fsnotify watcher and close the current one, triggering a refresh on the watcher goroutine.
		fsnotifyErr.ErrorNTimes(1)
		w.fsWatcher.Close()

		Eventually(fsnotifyActivity.Poll, "3s").Should(BeFalse())

		err = writer.WriteStatusFile("pod1", "name: pod1, status: active")
		Expect(err).ShouldNot(HaveOccurred())

		Eventually(haveEvents, "15s", "1s").WithArguments(filePath, []string{"create", "update", "update"}).Should(BeTrue())
		Eventually(lastInSync).Should(BeTrue())
	})
})
