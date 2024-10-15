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

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/projectcalico/calico/felix/deltatracker"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
)

const (
	dirStatus  = "endpoint-status"
	statusUp   = "up"
	statusDown = "down"
)

// EndpointStatusFileReporter writes a file to the FS
// any time it sees an Endpoint go up in the dataplane.
//
//   - Currently only writes to a directory "status", creating
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
	// Interval between maintainence re-applies when dataplane is healthy.
	reapplyInterval time.Duration

	hostname string

	filesys
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

type filesys interface {
	Create(name string) (*os.File, error)
	Remove(name string) error
	Mkdir(name string, perm os.FileMode) error
	ReadDir(name string) ([]os.DirEntry, error)
}

type defaultFilesys struct{}

// Create wraps os.Create.
func (fs *defaultFilesys) Create(name string) (*os.File, error) {
	return os.Create(name)
}

// Remove wraps os.Remove.
func (fs *defaultFilesys) Remove(name string) error {
	return os.Remove(name)
}

// Mkdir wraps os.Mkdir.
func (fs *defaultFilesys) Mkdir(name string, perm os.FileMode) error {
	return os.Mkdir(name, perm)
}

// ReadDir wraps os.ReadDir.
func (fs *defaultFilesys) ReadDir(name string) ([]os.DirEntry, error) {
	return os.ReadDir(name)
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
		reapplyInterval:         10 * time.Second,
		filesys:                 &defaultFilesys{},
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

// WithFilesys allows shimming into filesystem calls.
func WithFilesys(f filesys) FileReporterOption {
	return func(fr *EndpointStatusFileReporter) {
		fr.filesys = f
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
	var retryTimerResetNeeded, resyncWithKernelNeeded bool

	// Timer channels are stored separately from the timer, and nilled-out when not needed.
	var retry, scheduledReapply *time.Timer
	var retryC, scheduledReapplyC <-chan time.Time
	logrus.Debug("Endpoint status file reporter running.")
	for {
		select {
		case <-ctx.Done():
			logrus.Debug("Context cancelled, cleaning up and stopping endpoint status file reporter...")
			fr.drainTimer(retry)
			fr.drainTimer(scheduledReapply)
			return

		case e, ok := <-fr.endpointUpdatesC:
			if !ok {
				logrus.Panic("Input channel closed unexpectedly")
			}

			switch e.(type) {
			case *proto.DataplaneInSync:
				logrus.Debug("DataplaneInSync received from upstream.")
				fr.inSyncWithUpstream = true
				resyncWithKernelNeeded = true

			default:
				logrus.WithField("endpoint", e).Debug("Handling endpoint update")
				fr.handleEndpointUpdate(e)
			}

		case <-retryC:
		case <-scheduledReapplyC:
			resyncWithKernelNeeded = true
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

		if fr.inSyncWithUpstream {
			// There may be no updates to apply here,
			// but that case will be close to a no-op.
			err := fr.reconcileStatusFiles()
			if err != nil {
				logrus.WithError(err).Warn("Encountered one or more errors while reconciling endpoint status dir. Queueing retry...")
				retryTimerResetNeeded = true
				resyncWithKernelNeeded = true
			}
		}

		// Timer leak-protection; stop timers check if we need to drain timer channels.
		fr.drainTimer(retry)
		fr.drainTimer(scheduledReapply)

		// Retry should be stopped in all cases by now, and retryC drained.
		// It's safe now to reset / nil-out resources.
		if retryTimerResetNeeded {
			retry = fr.resetStoppedTimerOrInit(retry, fr.bom.Step())
			retryC = retry.C
			retryTimerResetNeeded = false
		} else {
			// No need to nil-out our local timer channel var, as it's guaranteed to be drained anyway.
			fr.bom.reset()
		}

		// If we're in-sync and healthy (no retry queued), queue a periodic resync.
		// Useful in-case a 3rd-party is interfering with the dataplane underneath us.
		if fr.inSyncWithUpstream && retryC == nil {
			scheduledReapply = fr.resetStoppedTimerOrInit(scheduledReapply, fr.reapplyInterval)
			scheduledReapplyC = scheduledReapply.C
		}
	}
}

func (fr *EndpointStatusFileReporter) drainTimer(t *time.Timer) {
	if t == nil || t.Stop() {
		return
	}
	select {
	// Case where timer was not already drained.
	case <-t.C:
		// Case where timer was already drained.
	default:
	}
}

// Passed timer must be guaranteed stopped and drained if not-nil.
func (fr *EndpointStatusFileReporter) resetStoppedTimerOrInit(t *time.Timer, d time.Duration) *time.Timer {
	if t == nil {
		return time.NewTimer(d)
	}
	_ = t.Reset(d)
	return t
}

// A sub-call of SyncForever, not intended to be called outside the main loop.
// Updates delta tracker state to match the received update.
// Logs and discards errors generated from converting endpoint updates to endpoint keys.
func (fr *EndpointStatusFileReporter) handleEndpointUpdate(e interface{}) {
	switch m := e.(type) {
	case *proto.WorkloadEndpointStatusUpdate:
		if m.Id == nil {
			logrus.WithField("update", m).Warn("Couldn't handle nil WorkloadEndpointStatusUpdate")
			return
		}
		key := names.WorkloadEndpointIDToWorkloadEndpointKey(m.Id, fr.hostname)
		fn := names.WorkloadEndpointKeyToStatusFilename(key)

		if m.Status.Status == statusDown {
			logrus.WithField("update", e).Debug("Skipping WorkloadEndpointStatusUpdate with down status")
			fr.statusDirDeltaTracker.Desired().Delete(fn)
			return
		} else if m.Status.Status == statusUp {
			// Explicitly checking the opposite case here (rather than fallthrough)
			// in-case of a terrible failure where status is neither "up" nor "down".
			logrus.WithField("update", e).Debug("Handling WorkloadEndpointUpdate with up status")
			fr.statusDirDeltaTracker.Desired().Add(fn)
		} else {
			logrus.WithField("update", e).Warn("Skipping update with unrecognized status")
		}

	case *proto.WorkloadEndpointStatusRemove:
		if m.Id == nil {
			logrus.WithField("update", m).Warn("Couldn't handle nil WorkloadEndpointStatusRemove")
			return
		}
		key := names.WorkloadEndpointIDToWorkloadEndpointKey(m.Id, fr.hostname)
		fn := names.WorkloadEndpointKeyToStatusFilename(key)
		fr.statusDirDeltaTracker.Desired().Delete(fn)
	default:
		logrus.WithField("update", e).Debug("Skipping undesired endpoint update")
	}
}

// A sub-call of SyncForever.
// Overwrites our user-space representation of the kernel with a fresh snapshot.
func (fr *EndpointStatusFileReporter) resyncDataplaneWithKernel() error {
	// Load any pre-existing committed dataplane entries.
	entries, err := fr.ensureStatusDir(fr.endpointStatusDirPrefix)
	if err != nil {
		return err
	}

	return fr.statusDirDeltaTracker.Dataplane().ReplaceFromIter(func(f func(k string)) error {
		for _, entry := range entries {
			f(entry.Name())
		}
		return nil
	})
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
	logrus.WithField("filename", name).Debug("Writing endpoint-status file to status-dir")
	filename := filepath.Join(fr.endpointStatusDirPrefix, dirStatus, name)
	f, err := fr.filesys.Create(filename)
	if err != nil {
		return err
	}
	return f.Close()
}

func (fr *EndpointStatusFileReporter) deleteStatusFile(name string) error {
	filename := filepath.Join(fr.endpointStatusDirPrefix, dirStatus, name)
	return fr.filesys.Remove(filename)
}

// ensureStatusDir ensures there is a directory named "endpoint-status", within
// the parent dir specified by prefix. Attempts to create the dir if it doesn't exist.
// Returns all entries within the dir if any exist.
func (fr *EndpointStatusFileReporter) ensureStatusDir(prefix string) (entries []fs.DirEntry, err error) {
	filename := filepath.Join(prefix, dirStatus)

	entries, err = fr.filesys.ReadDir(filename)
	if err != nil && errors.Is(err, fs.ErrNotExist) {
		// Discard ErrNotExist and return the result of attempting to create it.
		return entries, fr.filesys.Mkdir(filename, fs.FileMode(0655))
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
