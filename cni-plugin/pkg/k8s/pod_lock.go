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

package k8s

import (
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"

	"github.com/gofrs/flock"
	"github.com/sirupsen/logrus"
)

// podLockBuckets is how many lock files pods hash into. A fixed set never needs cleaning up,
// at the cost of two pods occasionally waiting on each other.
const podLockBuckets = 256

// PodLockPath returns the lock file that serializes CNI ADDs for the given pod. Pods are
// hashed into a fixed set of files, so unrelated pods can share one.
func PodLockPath(namespace, pod string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(namespace + "/" + pod))
	return filepath.Join(podLockDir, fmt.Sprintf("%03d.lock", h.Sum32()%podLockBuckets))
}

// acquirePodLock holds the pod's lock until the returned function is called. An ADD that
// waited for it then sees everything the ADD ahead of it wrote, endpoint included. It is
// best-effort: a failure is logged and the ADD carries on without the lock.
func acquirePodLock(namespace, pod string, logger *logrus.Entry) func() {
	path := PodLockPath(namespace, pod)
	logger = logger.WithField("lockFile", path)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		logger.WithError(err).Error("Failed to make directory for the pod lock, continuing without it")
		return func() {}
	}

	lock := flock.New(path)
	if err := lock.Lock(); err != nil {
		logger.WithError(err).Error("Failed to take the pod lock, continuing without it")
		return func() {}
	}
	logger.Debug("Took the pod lock")

	return func() {
		if err := lock.Unlock(); err != nil {
			logger.WithError(err).Warn("Failed to release the pod lock; ignoring because the process is about to exit")
		}
	}
}
