// Copyright (c) 2024 Tigera, Inc. All rights reserved.
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

package wait

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"

	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
)

// ForEndpointReadyWithTimeout blocks until a status file for the given endpoint
// is seen in the provided directory. Unblocks with an error after exceeding timeout.
func ForEndpointReadyWithTimeout(policyDir string, endpoint *libapi.WorkloadEndpoint, timeout time.Duration) error {
	if endpoint == nil {
		logrus.Panic("Endpoint is nil")
	}

	key, err := names.V3WorkloadEndpointToWorkloadEndpointKey(endpoint)
	if err != nil {
		return fmt.Errorf("failed to convert endpoint to key: %w", err)
	}
	filename := names.WorkloadEndpointKeyToStatusFilename(key)
	log := logrus.WithFields(logrus.Fields{
		"policyDir":   policyDir,
		"namespace":   endpoint.Namespace,
		"workload":    endpoint.Name,
		"desiredFile": filename,
	})
	log.Debug("Waiting for workload's status file to appear")

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	err = waitUntilFileExists(ctx, policyDir, filename)
	if err != nil {
		return fmt.Errorf("timed out waiting for endpoint status file '%s': %w", filepath.Join(policyDir, filename), err)
	}

	return nil
}

// Unblocks without error when the designated file is seen in directory.
// Returns with error if context is cancelled before file is found.
func waitUntilFileExists(ctx context.Context, directory, filename string) error {
	log := logrus.WithFields(logrus.Fields{
		"directory":   directory,
		"disiredFile": filename,
	})

	retryInterval := 500 * time.Millisecond
	for {
		found, err := waitUntilFileExistsOrError(ctx, directory, filename)
		if err != nil {
			log.WithError(err).Info("Filesystem check failed. Scheduling retry...")
		} else if found {
			break
		}

		// Not found: ctx cancelled or error.
		select {
		case <-ctx.Done():
			goto exitFileNotFound
		case <-time.After(retryInterval):
			log.Info("Retrying filesystem check...")
		}
	}

	return nil

exitFileNotFound:
	return errors.New("file not found")
}

// Waits for a file to exist on disk.
//
// # Sets up a watcher and also stats the filesystem
//
// Returns the last error encountered, though
// more than one error may occurr before returning.
func waitUntilFileExistsOrError(ctx context.Context, directory, filename string) (found bool, err error) {
	log := logrus.WithFields(logrus.Fields{
		"directory":   directory,
		"desiredFile": filename,
	})

	watch, cleanup, err := startWatchForFile(ctx, directory, filename)
	if err != nil {
		log.WithError(err).Warn("Encountered an error while starting a filesystem watch, polling filesystem instead...")
	} else {
		defer cleanup()
	}

	// Always call a stat before continuing with watcher processing.
	// If watches are broken, the loop will then degrade into a poll.
	// If the watch is healthy, we should still stat in case we missed
	// the create event.
	found, err = statFile(directory, filename)
	if err != nil {
		log.WithError(err).Warn("Encountered an error polling filesystem for file.")
	} else if found {
		return true, nil
	}

	// In the case where the watcher was created, progress to
	// consuming watch events. Otherwise return error.
	if watch == nil {
		return false, err
	}
	log.Debug("Progressing to watch event processing")
	return watch()
}

// Starts a watcher in the given directory and returns:
//
//   - A blocking function which consumes watch events.
//
//   - func returns a bool indicating whether or not a create-type event was
//     seen for a file whose name matches the passed string.
//
//   - Returns non-nil error if an error is received from the watcher.
//
//   - A cleanup func which closes the watcher and ignores any errors
//     encountered while doing so.
//
//   - An error if one is encountered while setting up watcher boilerplate
//     (in-which-case other return values will be nil).
func startWatchForFile(ctx context.Context, directory, filename string) (func() (bool, error), func(), error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, nil, err
	}

	err = watcher.Add(directory)
	if err != nil {
		defer closeWatcherAndIgnoreErr(watcher)
		return nil, nil, err
	}

	watchFunc := func() (bool, error) {
		return waitForCreateEvent(ctx, watcher, filename)
	}
	cleanupFunc := func() {
		closeWatcherAndIgnoreErr(watcher)
	}
	return watchFunc, cleanupFunc, nil
}

// Processes events from watcher and returns a boolean indicating
// whether an event was seen for a file whose base matches filename.
//
// Will only return an error if an error event from the watcher is received.
//
// Returns false, and nil error if context is cancelled.
func waitForCreateEvent(ctx context.Context, watcher *fsnotify.Watcher, filename string) (bool, error) {
	log := logrus.WithFields(logrus.Fields{
		"watchedDirectories": watcher.WatchList(),
		"targetFilename":     filename,
	})

	if watcher == nil {
		log.Panic("watcher is nil")
	}

	for {
		select {
		case e := <-watcher.Events:
			log.WithField("eventName", e.Name).Debug("Received watch event")
			switch e.Op {
			case fsnotify.Create:
				if filepath.Base(e.Name) == filename {
					log.WithField("eventName", e.Name).Debug("FS 'Create' event seen for file. Firing notification and stopping watch")
					return true, nil
				}
			default:
			}

		case err := <-watcher.Errors:
			return false, err
		case <-ctx.Done():
			return false, nil
		}
	}
}

func closeWatcherAndIgnoreErr(w *fsnotify.Watcher) {
	err := w.Close()
	if err != nil {
		logrus.WithError(err).Debug("Ignoring error encountered while closing filesystem watch")
	}
}

func statFile(directory, filename string) (bool, error) {
	f, err := os.Stat(filepath.Join(directory, filename))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	} else if f != nil && f.Name() == filename {
		return true, nil
	}

	return false, err
}
