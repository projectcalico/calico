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
	"fmt"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/lib/std/chanutil"
)

// WatchFilesFn builds a closure that can be used to monitor the given files and send an update
// to the given channel when any of the files change.
func WatchFilesFn(updChan chan struct{}, files ...string) (func(), error) {
	fileWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("error creating file watcher: %s", err)
	}
	for _, file := range files {
		if err := fileWatcher.Add(file); err != nil {
			logrus.WithError(err).Warn("Error watching file for changes")
			continue
		}
		logrus.WithField("file", file).Debug("Watching file for changes")
	}

	return func() {
		// If we exit this function, make sure to close the file watcher and update channel.
		defer fileWatcher.Close()
		defer close(updChan)
		defer logrus.Info("File watcher closed")
		for {
			select {
			case event, ok := <-fileWatcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write {
					logrus.WithField("file", event.Name).Info("File changed, triggering update")
					_ = chanutil.WriteNonBlocking(updChan, struct{}{})
				}
			case err, ok := <-fileWatcher.Errors:
				if !ok {
					return
				}
				logrus.Errorf("error watching file: %s", err)
			}
		}
	}, nil
}
