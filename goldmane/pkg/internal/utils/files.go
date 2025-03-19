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
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/lib/std/chanutil"
)

// WatchFilesFn builds a closure that can be used to monitor the given files and send an update
// to the given channel when any of the files change.
//
// Note that we don't use fsnotify or a similar library here - the way that file projection in Kubernetes works relies on
// a number of temporary files being created, copied, and removed, which can pose problems for some file watching libraries.
// We generally don't need immediate updates on file changes, so we poll the files at a regular interval instead.
func WatchFilesFn(updChan chan struct{}, interval time.Duration, files ...string) (func(context.Context), error) {
	cached := map[string]string{}

	for _, file := range files {
		logrus.WithField("file", file).Debug("Watching file")
	}

	return func(ctx context.Context) {
		// If we exit this function, make sure to close the update channel.
		defer close(updChan)
		defer logrus.Warn("File watcher closed")

		for {
			if ctx.Err() != nil {
				return
			}

			for _, file := range files {
				logCtx := logrus.WithField("file", file)

				// Read the file.
				data, err := os.ReadFile(file)
				if err != nil {
					logrus.WithError(err).Errorf("Failed to read file %s", file)
					if errors.Is(err, os.ErrNotExist) {
						delete(cached, file)
					}
					if !chanutil.WriteNonBlocking(updChan, struct{}{}) {
						logCtx.Debug("file notification channel is full, dropping update")
					}
					continue
				}

				// Hash the file.
				hash := fmt.Sprintf("%x", sha256.Sum256(data))

				// Compare the hash to the cached hash.
				if cur, ok := cached[file]; !ok {
					// First time we've seen this file.
					logCtx.Debug("File added")
					cached[file] = hash
					continue
				} else if cur == hash {
					// No change.
					logCtx.Debug("File unchanged")
					continue
				}
				logCtx.Debug("File changed")

				// File changed - update the cache and send an update.
				cached[file] = hash
				if !chanutil.WriteNonBlocking(updChan, struct{}{}) {
					logCtx.Debug("file notification channel is full, dropping update")
				}
			}

			<-time.After(interval)
		}
	}, nil
}
