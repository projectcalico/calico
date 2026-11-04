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

package utils

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
	"github.com/sirupsen/logrus"
)

// ipamLockTimeout bounds the IPAM work done while holding the host-wide IPAM lock.
const ipamLockTimeout = 90 * time.Second

// UnlockFn releases a lock taken by AcquireIPAMLockBestEffort.
type UnlockFn func()

// WithIPAMLock runs fn holding the host-wide IPAM lock at lockPath, best effort as
// AcquireIPAMLockBestEffort describes. fn's context gets a 90 second timeout that starts only
// once the lock is held, since a thundering herd of ADDs can hold the lock for a long time.
// fn's context is still canceled when ctx is. The lock isn't reentrant, so fn must not take it
// again or run calico-ipam in-process.
func WithIPAMLock(ctx context.Context, lockPath string, fn func(context.Context) error) error {
	unlock := AcquireIPAMLockBestEffort(lockPath)
	defer unlock()

	ctx, cancel := context.WithTimeout(ctx, ipamLockTimeout)
	defer cancel()
	return fn(ctx)
}

// AcquireIPAMLockBestEffort attempts to acquire the IPAM file lock, blocking if needed.  If an error occurs
// (for example permissions or missing directory) then it returns immediately.  Returns a function that unlocks the
// lock again (or a no-op function if acquiring the lock failed). The lock is not reentrant, so the holder must not
// run calico-ipam in-process until it unlocks.
func AcquireIPAMLockBestEffort(path string) UnlockFn {
	logrus.Info("About to acquire host-wide IPAM lock.")
	if path == "" {
		path = ipamLockPath
	}
	err := os.MkdirAll(filepath.Dir(path), 0o777)
	if err != nil {
		logrus.WithError(err).Error("Failed to make directory for IPAM lock")

		// Fall through, still a slight chance the file is there for us to access.
	}
	ipamLock := flock.New(path)
	err = ipamLock.Lock()
	if err != nil {
		logrus.WithError(err).Error("Failed to grab IPAM lock, may contend for datastore updates")
		return func() {}
	}
	logrus.Info("Acquired host-wide IPAM lock.")
	return func() {
		err := ipamLock.Unlock()
		if err != nil {
			logrus.WithError(err).Warn("Failed to release IPAM lock; ignoring because process is about to exit.")
		} else {
			logrus.Info("Released host-wide IPAM lock.")
		}
	}
}
