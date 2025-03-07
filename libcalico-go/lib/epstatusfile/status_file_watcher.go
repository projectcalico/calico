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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
)

// FileWatcher monitors a directory and reports events (creation, update and deletion) on file updates.
// It tries to use fsnotify to watch the directory. If fsnotify fails, it switches to polling mode.

type Callbacks struct {
	OnFileCreation func(fileName string)
	OnFileUpdate   func(fileName string)
	OnFileDeletion func(fileName string)
}

type FileWatcher struct {
	dir       string
	lastState map[string]os.FileInfo
	mu        sync.Mutex
	stopChan  chan struct{}
	fsWatcher *fsnotify.Watcher

	pollTicker *time.Ticker

	pollC chan struct{}

	callbacks Callbacks
}

// NewWatcher creates a new Watcher instance.
func NewFileWatcher(dir string, pollIntervalSeconds int) *FileWatcher {
	pollTicker := time.NewTicker(time.Duration(pollIntervalSeconds) * time.Second)

	return &FileWatcher{
		dir:        dir,
		lastState:  make(map[string]os.FileInfo),
		stopChan:   make(chan struct{}),
		pollTicker: pollTicker,
		pollC:      make(chan struct{}),
	}
}

func (w *FileWatcher) SetCallbacks(callbacks Callbacks) {
	w.callbacks = callbacks
}

func (w *FileWatcher) Start() {
	go w.runWatcher()
}

func (w *FileWatcher) newFsnotifyWatcher() error {
	var err error
	w.fsWatcher, err = fsnotify.NewWatcher()
	if err != nil {
		log.WithError(err).Error("Error initializing fsnotify.")
		return err
	}

	err = w.fsWatcher.Add(w.dir)
	if err != nil {
		log.WithError(err).Error("Error adding directory to fsnotify.")
		return err
	}

	log.WithField("dir", w.dir).Info("Started watching directory via fsnotify.")
	return nil
}

func (w *FileWatcher) runFsnotifyWatcher(watcher *fsnotify.Watcher) error {
	// Listen for events and loop until error occurs.
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				// Stop if channel is closed.
				return fmt.Errorf("fsnotify channel is closed unexpectly")
			}
			log.WithFields(log.Fields{
				"file": event.Name,
				"op":   event.Op,
			}).Debug("received file events")

			filePath := event.Name
			if event.Op == fsnotify.Remove {
				w.callbacks.OnFileDeletion(filePath)
				delete(w.lastState, filePath)
			} else {
				fileInfo, err := os.Stat(filePath)
				if err != nil {
					log.WithError(err).Error("Failed to get file info on a fsnotify event.")
				} else if !fileInfo.IsDir() {
					if event.Op == fsnotify.Create {
						w.lastState[filePath] = fileInfo
						w.callbacks.OnFileCreation(filePath)
					}
					if event.Op == fsnotify.Write {
						w.lastState[filePath] = fileInfo
						w.callbacks.OnFileUpdate(filePath)
					}
				}
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				// Stop if channel is closed.
				return fmt.Errorf("fsnotify channel is closed unexpectly")
			}
			log.WithError(err).Error("fsnotify error. Falling back to polling.")
			return err
		case <-w.stopChan:
			return nil
		}
	}
}

// Start begins watching the directory.
func (w *FileWatcher) runWatcher() {
	// Get current state of the directory and emit initial events.
	w.scanDirectory()

	for {
		// Try to get a fsnotify watcher if possible.
		err := w.newFsnotifyWatcher()
		if err != nil {
			log.WithError(err).Info("Error initializing fsnotify. Falling back to polling.")
		} else {
			defer w.fsWatcher.Close()
		}

		if w.fsWatcher != nil {
			// Run fsnotify watcher loop if possible.
			err := w.runFsnotifyWatcher(w.fsWatcher)
			if err != nil {
				// fall back to polling.
				log.Info("Start polling directory on updates.")
				w.pollC <- struct{}{}
			} else {
				// Watcher stopped by us.
				return
			}
		}

		select {
		case <-w.pollC:
		case <-w.pollTicker.C:
			w.scanDirectory()
		case <-w.stopChan:
			return
		}
	}
}

// scanDirectory detects file creations, modifications, and deletions.
func (w *FileWatcher) scanDirectory() {
	w.mu.Lock()
	defer w.mu.Unlock()

	currentState := make(map[string]os.FileInfo)

	err := filepath.Walk(w.dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			currentState[path] = info
		}
		return nil
	})
	if err != nil {
		log.WithError(err).Error("Error reading directory")
		return
	}

	// Detect new or modified files.
	for path, info := range currentState {
		oldInfo, exists := w.lastState[path]
		if !exists {
			log.WithField("file", path).Debug("New file detected")
			w.callbacks.OnFileCreation(path)
		} else if oldInfo.ModTime() != info.ModTime() {
			log.WithField("file", path).Debug("File modified")
			w.callbacks.OnFileUpdate(path)
		}
	}

	// Detect deleted files.
	for path := range w.lastState {
		if _, exists := currentState[path]; !exists {
			log.WithField("file", path).Debug("File deleted")
			w.callbacks.OnFileDeletion(path)
		}
	}

	// Update lastState for next iteration.
	w.lastState = currentState
}

// Stop stops the watcher.
func (w *FileWatcher) Stop() {
	close(w.stopChan)
	if w.fsWatcher != nil {
		w.fsWatcher.Close()
	}
}

func GetWorkloadEndpointStatusFromFile(filePath string) (*WorkloadEndpointStatus, error) {
	logCxt := log.WithField("file", filePath)

	// Read the file contents.
	data, err := os.ReadFile(filePath)
	if err != nil {
		logCxt.WithError(err).Error("Failed to read file content.")
		return nil, err
	}

	logCxt.WithField("content", string(data)).Debug("Endpoint status from file")

	// Unmarshal JSON into a struct.
	var epStatus WorkloadEndpointStatus
	err = json.Unmarshal(data, &epStatus)
	if err != nil {
		logCxt.WithError(err).Error("Failed to unmarshal JSON")
		return nil, err
	}

	return &epStatus, nil
}
