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
	dirStatus = "status"
)

// EndpointStatusFileReporter writes a file to the FS
// any time it sees an Endpoint go up in the dataplane.
//
//   - Currently only writes to a directory "policy", creating
//     an entry for each workload, when each workload's
//     policy is programmed for the first time.
type EndpointStatusFileReporter struct {
	endpointUpdatesC        <-chan interface{}
	endpointStatusDirPrefix string

	// DeltaTracker for the policy subdirectory
	statusDirDeltaTracker *deltatracker.SetDeltaTracker[string]
	inSyncWithUpstream    bool

	// Wraps and manages a real or mock wait.Backoff.
	bom backoffManager

	hostname string
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
	statusDirPath string,
	opts ...FileReporterOption,
) *EndpointStatusFileReporter {

	sr := &EndpointStatusFileReporter{
		endpointUpdatesC:        endpointUpdatesC,
		endpointStatusDirPrefix: statusDirPath,
		statusDirDeltaTracker:   deltatracker.NewSetDeltaTracker[string](),
		bom:                     newBackoffManager(newDefaultBackoff),
		hostname:                "",
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

// WithHostname instructs the reporter to use the give hostname
// when creating endpoint structures.
func WithHostname(hostname string) FileReporterOption {
	return func(fr *EndpointStatusFileReporter) {
		fr.hostname = hostname
	}
}

// SyncForever blocks until ctx is cancelled.
// Continuously pulls status-updates from updates C,
// and reconciles the filesystem with internal state.
func (fr *EndpointStatusFileReporter) SyncForever(ctx context.Context) {
	// State flags influencing the loop.
	// Each flag triggers one behaviour within the loop.
	// Once the behaviour succeeds, the flag is switched off.
	// If the behaviour fails, the flag is left on, and a retry is queued.
	var retryTimerResetNeeded, resyncWithKernelNeeded, applyToKernelNeeded, exit bool

	// Timer channels are stored separately from the timer, and nilled-out when not needed.
	var retry, scheduledReapply *time.Timer
	var retryC, scheduledReapplyC <-chan time.Time
	reapplyInterval := 10 * time.Second
	logrus.Debug("Endpoint status file reporter running.")
	for {
		select {
		case <-ctx.Done():
			logrus.Debug("Context cancelled, cleaning up and stopping endpoint status file reporter...")
			retryTimerResetNeeded, resyncWithKernelNeeded, applyToKernelNeeded = false, false, false
			exit = true

		case e, ok := <-fr.endpointUpdatesC:
			if !ok {
				logrus.Panic("Input channel closed unexpectedly")
			}

			switch e.(type) {
			case *proto.DataplaneInSync:
				logrus.Debug("DataplaneInSync received from upstream.")
				fr.inSyncWithUpstream = true
				resyncWithKernelNeeded = true
				applyToKernelNeeded = true

			default:
				logrus.WithField("endpoint", e).Debug("Handling endpoint update")
				fr.handleEndpointUpdate(e)
				if fr.inSyncWithUpstream {
					applyToKernelNeeded = true
				}
			}

		case <-retryC:
		case <-scheduledReapplyC:
			resyncWithKernelNeeded, applyToKernelNeeded = true, true
		}

		if resyncWithKernelNeeded {
			err := fr.resyncDataplaneWithKernel()
			if err != nil {
				logrus.WithError(err).Warn("Encountered an error while resyncing state with kernel. Queueing retry...")
				retryTimerResetNeeded = true
			} else {
				resyncWithKernelNeeded = false
			}
		}

		if applyToKernelNeeded {
			err := fr.reconcileStatusFiles()
			if err != nil {
				logrus.WithError(err).Warn("Encountered one or more errors while reconciling endpoint status dir. Queueing retry...")
				retryTimerResetNeeded = true
			} else {
				applyToKernelNeeded = false
			}
		}

		// Timer leak-protection; check if we need to drain retryC.
		if retry != nil && !retry.Stop() {
			select {
			case <-retry.C:
				// Timer fired but another channel was selected (retryC was not drained).
			default:
				// Timer fired and was drained by the select.
			}
		}
		// Always stop the reapply timer after any operation
		// to avoid doubling-up applies in quick succession.
		if scheduledReapply != nil && !scheduledReapply.Stop() {
			select {
			case <-scheduledReapply.C:
			default:
			}
		}

		// Cleanup done, safe to exit.
		if exit {
			return
		}

		// Retry should be stopped in all cases by now, and retryC drained.
		// It's safe now to reset / nil-out resources.
		if retryTimerResetNeeded {
			if retry == nil {
				retry = time.NewTimer(fr.bom.Step())
			} else {
				retry.Reset(fr.bom.Step())
			}
			retryC = retry.C
			retryTimerResetNeeded = false
		} else {
			fr.bom.reset()
			// Nil channels will never be selected.
			retryC = nil
		}

		// If we're in-sync and healthy (no retry queued), queue a periodic resync.
		// Useful in-case a 3rdparty is interfering with the dataplane underneath us.
		if fr.inSyncWithUpstream && retryC == nil {
			if scheduledReapply == nil {
				scheduledReapply = time.NewTimer(reapplyInterval)
			} else {
				scheduledReapply.Reset(reapplyInterval)
			}
			scheduledReapplyC = scheduledReapply.C
		}
	}
}

// A sub-call of SyncForever, not intended to be called outside the main loop.
// Updates delta tracker state to match the received update.
//
// If commitToKernel is true, attempts to commit the new state to the kernel.
//
// Can only return an error after a failed commit, so a returned error should
// always result in SyncForever queueing a retry.
func (fr *EndpointStatusFileReporter) handleEndpointUpdate(e interface{}) {
	switch m := e.(type) {
	case *proto.WorkloadEndpointStatusUpdate:
		key := names.WorkloadEndpointIDToWorkloadEndpointKey(m.Id, fr.hostname)
		if key == nil {
			logrus.WithField("update", e).Warn("Couldn't generate a WorkloadEndpointKey from update")
		}
		fr.statusDirDeltaTracker.Desired().Add(names.WorkloadEndpointKeyToStatusFilename(key))
	case *proto.WorkloadEndpointStatusRemove:
		key := names.WorkloadEndpointIDToWorkloadEndpointKey(m.Id, fr.hostname)
		if key == nil {
			logrus.WithField("update", e).Warn("Couldn't generate a WorkloadEndpointKey from update")
		}
		fr.statusDirDeltaTracker.Desired().Delete(names.WorkloadEndpointKeyToStatusFilename(key))
	default:
		logrus.WithField("update", e).Debug("Skipping undesired endpoint update")
	}
}

// Overwrites our user-space representation of the kernel with a fresh snapshot.
func (fr *EndpointStatusFileReporter) resyncDataplaneWithKernel() error {
	// Load any pre-existing committed dataplane entries.
	entries, err := ensureStatusDir(fr.endpointStatusDirPrefix)
	if err != nil {
		return err
	}

	fr.statusDirDeltaTracker.Dataplane().ReplaceFromIter(func(f func(k string)) error {
		for _, entry := range entries {
			f(entry.Name())
		}
		return nil
	})

	return nil
}

// A sub-call of SyncForever. Not intended to be called outside the main loop.
// Applies pending updates and deletes pending deletions.
func (fr *EndpointStatusFileReporter) reconcileStatusFiles() error {
	var lastError error
	fr.statusDirDeltaTracker.PendingUpdates().Iter(func(name string) deltatracker.IterAction {
		err := fr.writeStatusFile(name)
		if err != nil {
			if !errors.Is(err, fs.ErrExist) {
				lastError = err
				return deltatracker.IterActionNoOp
			}
		}
		return deltatracker.IterActionUpdateDataplane
	})

	fr.statusDirDeltaTracker.PendingDeletions().Iter(func(name string) deltatracker.IterAction {
		err := fr.deleteStatusFile(name)
		if err != nil {
			// Carry on as normal (with a warning) if the file is somehow already deleted.
			if !errors.Is(err, fs.ErrNotExist) {
				lastError = err
				return deltatracker.IterActionNoOp
			}
			logrus.WithField("file", name).Warn("Ignoring error; attempted to delete file which does not exist")
		}
		return deltatracker.IterActionUpdateDataplane
	})

	return lastError
}

func (fr *EndpointStatusFileReporter) writeStatusFile(name string) error {
	// Write file to dir.
	filename := filepath.Join(fr.endpointStatusDirPrefix, dirStatus, name)
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	return f.Close()
}

func (fr *EndpointStatusFileReporter) deleteStatusFile(name string) error {
	filename := filepath.Join(fr.endpointStatusDirPrefix, dirStatus, name)
	return os.Remove(filename)
}

// ensureStatusDir ensures there is a directory named "status", within
// the parent dir specified by prefix. Attempts to create the dir if it doesn't exist.
// Returns all entries within the dir if any exist.
func ensureStatusDir(prefix string) (entries []fs.DirEntry, err error) {
	filename := filepath.Join(prefix, dirStatus)

	entries, err = os.ReadDir(filename)
	if err != nil && errors.Is(err, fs.ErrNotExist) {
		// Discard ErrNotExist and return the result of attempting to create it.
		return entries, os.Mkdir(filename, fs.FileMode(0644))
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
