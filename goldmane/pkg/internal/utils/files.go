// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package utils

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/lib/std/chanutil"
)

// WatchFilesFn builds a closure that can be used to monitor the given files and send an update
// to the given channel when any of the files change.
func WatchFilesFn(updChan chan struct{}, files ...string) (func(context.Context), error) {
	fileWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("error creating file watcher: %s", err)
	}

	watchedDirs := map[string]struct{}{}
	for _, file := range files {
		if file == "" {
			continue
		}

		// There is a bug in fsnotify where some events are not triggered on files. So watch the directory -
		// this ensures we catch all events. Longer term, moving off of fsnotify would be a good idea.
		dir := filepath.Dir(file)
		if _, ok := watchedDirs[dir]; ok {
			// Already watching this directory.
			continue
		}

		if err := fileWatcher.Add(dir); err != nil {
			logrus.WithError(err).Warn("Error watching directory for changes")
			continue
		}
		logrus.WithField("dir", dir).Debug("Watching directory for changes")
		watchedDirs[dir] = struct{}{}
	}

	return func(ctx context.Context) {
		for dir := range watchedDirs {
			logrus.WithField("dir", dir).Info("Starting watch on directory")
		}

		// If we exit this function, make sure to close the file watcher and update channel.
		defer fileWatcher.Close()
		defer close(updChan)
		defer logrus.Warn("File watcher closed")
		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-fileWatcher.Events:
				if !ok {
					logrus.Warn("File watcher events channel closed")
					return
				}
				if !chanutil.WriteNonBlocking(updChan, struct{}{}) {
					logrus.WithField("event", event).Debug("file notification channel is full, dropping update")
				}
			case err, ok := <-fileWatcher.Errors:
				if !ok {
					logrus.Warn("File watcher errors channel closed")
					return
				}
				logrus.Errorf("error watching file: %s", err)
			}
		}
	}, nil
}
