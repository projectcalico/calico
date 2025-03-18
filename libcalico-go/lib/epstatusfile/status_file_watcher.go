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

	callbacks Callbacks

	// Shim function variable to get a new watcher
	newFsnotifyWatcherFunc func() (*fsnotify.Watcher, error)

	// variable for UT
	fsnotifyActive bool
}

// NewWatcher creates a new Watcher instance.
func NewFileWatcher(dir string, pollInterval time.Duration) *FileWatcher {
	return NewFileWatcherWithShim(dir, pollInterval, fsnotify.NewWatcher)
}

// NewWatcher creates a new Watcher instance.
func NewFileWatcherWithShim(dir string, pollInterval time.Duration, newFsnotifyWatcherFunc func() (*fsnotify.Watcher, error)) *FileWatcher {
	pollTicker := time.NewTicker(pollInterval)

	return &FileWatcher{
		dir:                    dir,
		lastState:              make(map[string]os.FileInfo),
		stopChan:               make(chan struct{}),
		pollTicker:             pollTicker,
		newFsnotifyWatcherFunc: newFsnotifyWatcherFunc,
	}
}

func (w *FileWatcher) SetCallbacks(callbacks Callbacks) {
	w.callbacks = callbacks
}

func (w *FileWatcher) Start() {
	go w.runWatcher()

}

func (w *FileWatcher) newFsnotifyWatcher() error {
	// reset w.fsWatcher
	w.fsWatcher = nil

	watcher, err := w.newFsnotifyWatcherFunc()
	if err != nil {
		log.WithError(err).Error("Error initializing fsnotify.")
		return err
	}

	err = watcher.Add(w.dir)
	if err != nil {
		log.WithError(err).Error("Error adding directory to fsnotify.")
		return err
	}

	w.fsWatcher = watcher
	log.WithField("dir", w.dir).Info("Started watching directory via fsnotify.")
	return nil
}

func (w *FileWatcher) runFsnotifyWatcher(watcher *fsnotify.Watcher) error {
	w.fsnotifyActive = true

	// Get current state of the directory and emit initial events.
	w.scanDirectory()

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
	defer func() {
		if w.fsWatcher != nil {
			defer w.fsWatcher.Close()
		}
	}()

	for {
		// Try to get a fsnotify watcher if possible.
		err := w.newFsnotifyWatcher()
		if err != nil {
			log.WithError(err).Info("Error initializing fsnotify. Falling back to polling.")
		}

		if w.fsWatcher != nil {
			// Run fsnotify watcher loop if possible.
			err := w.runFsnotifyWatcher(w.fsWatcher)
			w.fsnotifyActive = false
			if err != nil {
				// fall back to polling.
				log.WithError(err).Info("Start polling directory on updates.")
			} else {
				// Watcher stopped by us.
				return
			}
		}

		select {
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

	entries, err := os.ReadDir(w.dir)
	if err != nil {
		log.WithError(err).Error("Error reading directory")
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue // Skip subdirectories
		}

		info, err := entry.Info() // Convert DirEntry to FileInfo
		if err != nil {
			log.WithError(err).WithField("file", entry.Name()).Error("Error getting file info")
			continue
		}

		path := filepath.Join(w.dir, entry.Name()) // Get full path
		currentState[path] = info
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
}
