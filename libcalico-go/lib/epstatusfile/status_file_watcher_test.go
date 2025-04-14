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
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/fsnotify/fsnotify"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var newFsnotifyWatcherErr bool

type eventRecorder struct {
	fileNameToEvents map[string][]string
	inSyncEvents     []bool
}

func newEventRecorder() *eventRecorder {
	return &eventRecorder{
		fileNameToEvents: make(map[string][]string),
	}
}

func (e *eventRecorder) OnFileEvent(fileName string, event string) {
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
	e.inSyncEvents = append(e.inSyncEvents, s)
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

func newFsnotifyWatcherShim() (*fsnotify.Watcher, error) {
	if newFsnotifyWatcherErr {
		return nil, fmt.Errorf("simulating an errro on initializing fsnotify")
	}
	return fsnotify.NewWatcher()
}

var _ = Describe("Workload endpoint status file watcher test", func() {
	var w *FileWatcher
	var r *eventRecorder

	tmpPath := "/go/src/github.com/projectcalico/calico/ut-tmp-dir"
	statusDir := tmpPath + "/endpoint-status"
	err := os.MkdirAll(statusDir, 0755)
	Expect(err).ShouldNot(HaveOccurred())

	writer := NewEndpointStatusFileWriter(tmpPath)

	notifyActive := func() bool {
		return w.fsnotifyActive
	}

	haveEvents := func(filePath string, expected []string) bool {
		// The kernel can fire many WRITE events for a single logical write, if the data is truncated.
		// So, it's error-prone to check our sequence of logical events is directly-equivalent to the actual.
		// Instead, we check that the logical sequence exists within the actual sequence, which should account for duplicates.
		events, exist := r.fileNameToEvents[filePath]
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
		if len(r.inSyncEvents) == 0 {
			return false
		}
		return r.inSyncEvents[len(r.inSyncEvents)-1]
	}

	BeforeEach(func() {
		clearDir(statusDir)

		w = NewFileWatcherWithShim(statusDir, 10*time.Second, newFsnotifyWatcherShim)
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
		Eventually(notifyActive, "3s").Should(BeTrue())

		filePath := filepath.Join(statusDir, "pod1")
		Eventually(haveEvents, "5s", "1s").WithArguments(filePath, []string{"create"}).Should(BeTrue())
		Eventually(r.inSyncEvents).ShouldNot(BeEmpty())

		Eventually(lastInSync).Should(BeTrue())
	})

	It("should receive events on files been updated", func() {
		err = writer.WriteStatusFile("pod1", "name: pod1")
		Expect(err).ShouldNot(HaveOccurred())

		w.Start()
		defer w.Stop()
		Eventually(notifyActive, "3s").Should(BeTrue())

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
		Eventually(notifyActive, "3s").Should(BeTrue())

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
		Eventually(notifyActive, "3s").Should(BeTrue())

		err = writer.WriteStatusFile("pod1", "name: pod1")
		Expect(err).ShouldNot(HaveOccurred())

		filePath := filepath.Join(statusDir, "pod1")
		Eventually(haveEvents, "5s", "1s").WithArguments(filePath, []string{"create", "update"}).Should(BeTrue())
		Eventually(lastInSync).Should(BeTrue())

		// Similate an error on new fsnotify watcher and close the current one.
		newFsnotifyWatcherErr = true
		defer func() { newFsnotifyWatcherErr = false }()
		w.fsWatcher.Close()

		Eventually(notifyActive, "3s").Should(BeFalse())

		err = writer.WriteStatusFile("pod1", "name: pod1, status: active")
		Expect(err).ShouldNot(HaveOccurred())

		Eventually(haveEvents, "15s", "1s").WithArguments(filePath, []string{"create", "update", "update"}).Should(BeTrue())
		Eventually(lastInSync).Should(BeTrue())
	})
})
