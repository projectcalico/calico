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

package statusrep

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/projectcalico/calico/felix/deltatracker"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/names"

	"github.com/sirupsen/logrus"
)

const (
	dirPolicyStatus = "policy"
)

// EndpointStatusFileReporter writes a file to the FS
// any time it sees an Endpoint go up in the dataplane.
//
//   - Currently only writes to a directory "policy", creating
//     an entry for each workload, when each workload's
//     policy is programmed for the first time.
type EndpointStatusFileReporter struct {
	inSyncC                 <-chan bool
	endpointUpdatesC        <-chan interface{}
	endpointStatusDirPrefix string

	// DeltaTracker for the policy subdirectory
	policyDirDeltaTracker *deltatracker.SetDeltaTracker[string]

	// Wraps and manages a real or mock wait.Backoff.
	bom backoffManager
}

// Backoff wraps a timer-based-retry type which can be stepped.
type Backoff interface {
	Step() time.Duration
}

// backoffManager wraps and manages a real or mock wait.Backoff.
type backoffManager struct {
	Backoff
	newBackoffFunc func() Backoff
}

// newBackoffManager creates a backoffManager which uses the
// passed func to create backoffs.
func newBackoffManager(newBackoffFunc func() Backoff) backoffManager {
	return backoffManager{
		Backoff:        newBackoffFunc(),
		newBackoffFunc: newBackoffFunc,
	}
}

// Reset the manager's backoff to its original state.
func (bom *backoffManager) reset() {
	bom.Backoff = bom.newBackoffFunc()
}

// Gets the manager's backoff.
func (bom *backoffManager) getBackoff() Backoff {
	return bom.Backoff
}

// FileReporterOption allows modification of a new EndpointStatusFileReporter.
type FileReporterOption func(*EndpointStatusFileReporter)

// NewEndpointStatusFileReporter creates a new EndpointStatusFileReporter.
func NewEndpointStatusFileReporter(
	endpointUpdatesC <-chan interface{},
	inSyncC <-chan bool,
	statusDirPath string,
	opts ...FileReporterOption,
) *EndpointStatusFileReporter {

	sr := &EndpointStatusFileReporter{
		inSyncC:                 inSyncC,
		endpointUpdatesC:        endpointUpdatesC,
		endpointStatusDirPrefix: statusDirPath,
		policyDirDeltaTracker:   deltatracker.NewSetDeltaTracker[string](),
		bom:                     newBackoffManager(newDefaultBackoff),
	}

	for _, o := range opts {
		o(sr)
	}

	return sr
}

// WithNewBackoffFunc returns a FileReporterOption which alters the backoff
// used by the reporter's backoff manager.
func WithNewBackoffFunc(newBackoffFunc func() Backoff) FileReporterOption {
	return func(fr *EndpointStatusFileReporter) {
		fr.bom = newBackoffManager(newBackoffFunc)
	}
}

// SyncForever blocks until ctx is cancelled.
// Continuously pulls status-updates from updates C,
// and reconciles the filesystem with internal state.
func (fr *EndpointStatusFileReporter) SyncForever(ctx context.Context) {
	inSyncWithUpstream := false
	var retryC, scheduledResync <-chan time.Time // Starts out as nil, ignored by selects.

	logrus.Warn("Endpoint status file reporter running.")
	for {
		select {
		case <-ctx.Done():
			logrus.Warn("Context cancelled, stopping...")
			return
		case b, ok := <-fr.inSyncC:
			if !ok {
				logrus.Panic("InSync channel closed unexpectedly.")
			}

			if b == true {
				logrus.Warn("InSync received from calc graph.")
				inSyncWithUpstream = true
				err := fr.syncForeverReconcilePolicyFiles(true)
				if err != nil {
					retryC = time.After(fr.bom.Step())
				} else {
					// Ensure backoff-retries are reset/off in the case of success.
					fr.bom.reset()
					retryC = nil
				}
			}
		case e, ok := <-fr.endpointUpdatesC:
			if !ok {
				logrus.Panic("Input channel closed unexpectedly")
			}
			logrus.WithField("endpoint", e).Warn("Handling endpoint update")

			err := fr.syncForeverHandleEndpointUpdate(e, inSyncWithUpstream)
			if err != nil {
				logrus.WithError(err).Warn("Encountered an error while handling an endpoint update. Queueing retry...")
				retryC = time.After(fr.bom.Step())
			} else {
				fr.bom.reset()
				retryC = nil
			}
		case _, ok := <-retryC:
			if !ok {
				logrus.Panic("Retry channel closed unexpectedly")
			}

			err := fr.syncForeverReconcilePolicyFiles(true)
			if err != nil {
				backoffDuration := fr.bom.Step()
				logrus.WithError(err).WithField("backoff", backoffDuration.String()).
					Warn("Encountered an error during a retried update. Will retry again after a backoff...")

				retryC = time.After(backoffDuration)
			} else {
				retryC = nil
				fr.bom.reset()
			}
		case _, ok := <-scheduledResync:
			if !ok {
				logrus.Panic("Internal scheduled-resync channel closed unexpectedly")
			}

			err := fr.syncForeverReconcilePolicyFiles(true)
			if err != nil {
				backoffDuration := fr.bom.Step()
				logrus.WithError(err).WithField("backoff", backoffDuration.String()).
					Warn("Encountered an error during a scheduled re-sync. Queueing retry...")
			}
		}
	}
}

// A sub-call of SyncForever, not intended to be called outside the main loop.
// Updates delta tracker state to match the received update.
// If commitToKernel is true, attempts to commit the new state to the kernel.
// Can only return an error after a failed commit, so a returned error should
// always result in SyncForever queueing a retry.
func (fr *EndpointStatusFileReporter) syncForeverHandleEndpointUpdate(e interface{}, commitToKernel bool) error {
	switch m := e.(type) {
	case *proto.WorkloadEndpointStatusUpdate:
		fr.policyDirDeltaTracker.Desired().Add(names.WorkloadEndpointIDToStatusFilename(m.Id))
	case *proto.WorkloadEndpointStatusRemove:
		fr.policyDirDeltaTracker.Desired().Delete(names.WorkloadEndpointIDToStatusFilename(m.Id))
	default:
		logrus.WithField("update", e).Warn("Skipping unrecognized endpoint update")
		return nil
	}

	if commitToKernel {
		err := fr.syncForeverReconcilePolicyFiles(false)
		if err != nil {
			return fmt.Errorf("Couldn't reconcile policy-status: %w", err)
		}
	}

	return nil
}

func (fr *EndpointStatusFileReporter) syncForeverReconcilePolicyFiles(fullResync bool) error {
	if fullResync {
		// If calling this due to the first in-sync msg from upstream,
		// this will be a no-op.
		fr.policyDirDeltaTracker.Dataplane().DeleteAll()

		// Load any existing committed dataplane entries.
		entries, err := ensurePolicyStatusDir(fr.endpointStatusDirPrefix)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			fr.policyDirDeltaTracker.Dataplane().Add(entry.Name())
		}
	}

	var lastError error
	fr.policyDirDeltaTracker.PendingUpdates().Iter(func(name string) deltatracker.IterAction {
		err := fr.writePolicyFile(name)
		if err != nil {
			logrus.WithError(err).Warn("Failed to write file to policy-status dir")
			lastError = err
			return deltatracker.IterActionNoOp
		}

		return deltatracker.IterActionUpdateDataplane
	})

	fr.policyDirDeltaTracker.PendingDeletions().Iter(func(name string) deltatracker.IterAction {
		err := fr.deletePolicyFile(name)
		if err != nil {
			logrus.WithError(err).Warn("Failed to delete file in policy-status-dir")
			// Carry on as normal (with a warning) if the file is somehow already deleted.
			if !errors.Is(err, fs.ErrNotExist) {
				lastError = err
				return deltatracker.IterActionNoOp
			}
		}

		return deltatracker.IterActionUpdateDataplane
	})

	return lastError
}

func (fr *EndpointStatusFileReporter) writePolicyFile(name string) error {
	// Write file to dir.
	filename := filepath.Join(fr.endpointStatusDirPrefix, dirPolicyStatus, name)
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	return f.Close()
}

func (fr *EndpointStatusFileReporter) deletePolicyFile(name string) error {
	filename := filepath.Join(fr.endpointStatusDirPrefix, dirPolicyStatus, name)
	return os.Remove(filename)
}

// ensurePolicyStatusDir ensures there is a directory named "policy", within
// the parent dir specified by prefix. Attempts to create the dir if it doesn't exist.
// Returns all entries within the dir if any exist.
func ensurePolicyStatusDir(prefix string) (entries []fs.DirEntry, err error) {
	filename := filepath.Join(prefix, dirPolicyStatus)

	entries, err = os.ReadDir(filename)
	if err != nil && errors.Is(err, fs.ErrNotExist) {
		// Discard ErrNotExist and return the result of attempting to create it.
		return entries, os.Mkdir(filename, 0644)
	}

	return entries, err
}

func newDefaultBackoff() Backoff {
	return &wait.Backoff{
		Duration: 50 * time.Millisecond,
		Factor:   10,
		Jitter:   0,
		Steps:    3,
		Cap:      5 * time.Second,
	}
}
