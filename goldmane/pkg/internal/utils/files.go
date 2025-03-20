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
	"io"
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
		hash, err := getFileHash(file)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		} else if hash != "" {
			cached[file] = hash
		}
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
				logCtx.Debug("Checking file")

				// Hash the file.
				hash, err := getFileHash(file)
				if err != nil {
					if !errors.Is(err, os.ErrNotExist) {
						logrus.WithError(err).Errorf("Failed to hash file %s", file)
						continue
					}

					if _, ok := cached[file]; ok {
						logCtx.Debug("File removed")
						if !chanutil.WriteNonBlocking(updChan, struct{}{}) {
							logCtx.Debug("file notification channel is full, dropping update")
						}
						delete(cached, file)
						continue
					} else {
						logCtx.Debug("File does not exist")
						continue
					}
				}

				// Compare the hash to the cached hash.
				if cur, ok := cached[file]; ok && cur == hash {
					// No change.
					logCtx.Debug("File unchanged")
					continue
				} else if !ok {
					logCtx.Debug("File created")
				} else {
					logCtx.Debug("File changed")
				}

				// File changed or created - update the cache and send an update.
				cached[file] = hash
				if !chanutil.WriteNonBlocking(updChan, struct{}{}) {
					logCtx.Debug("file notification channel is full, dropping update")
				}
			}

			<-time.After(interval)
		}
	}, nil
}

func getFileHash(file string) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}
