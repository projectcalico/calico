// Copyright (c) 2016-2019 Tigera, Inc. All rights reserved.
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

	"github.com/projectcalico/calico/felix/proto"

	"github.com/sirupsen/logrus"
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
	statusDirPath string,
	opts ...FileReporterOption,
) *EndpointStatusFileReporter {

	sr := &EndpointStatusFileReporter{
		endpointUpdatesC:        make(<-chan interface{}),
		endpointStatusDirPrefix: statusDirPath,

		bom: newBackoffManager(newDefaultBackoff),
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
// Continuously pulls from endpoint-updates C,
// and writes files to the status directory.
func (fr *EndpointStatusFileReporter) SyncForever(ctx context.Context) {
	recreatePolicyDir := true
	for {
		if recreatePolicyDir {
			logrus.Debug("Creating/truncating policy status directory")
			err := ensurePolicyStatusDir(fr.endpointStatusDirPrefix, true)
			if err != nil {
				logrus.WithError(err).Warn("Failed to create policy status directory; queueing retry...")
				select {
				case <-ctx.Done():
					logrus.Debug("Context cancelled; stopping...")
					return
				case <-time.After(fr.bom.getBackoff().Step()):
					continue
				}
			} else {
				// Reset backoff.
				fr.bom.reset()
				recreatePolicyDir = false
			}
		}

		select {
		case <-ctx.Done():
			logrus.Debug("Context cancelled, stopping...")
			return
		case e, ok := <-fr.endpointUpdatesC:
			logrus.WithField("endpoint", e).Debug("Handling endpoint update")
			if !ok {
				logrus.Panic("Input channel closed unexpectedly")
			}
			switch m := e.(type) {
			case *proto.WorkloadEndpointStatusUpdate:
				// Write file to dir.
				filename := filepath.Join(fr.endpointStatusDirPrefix, m.Id.WorkloadId)
				f, err := os.Create(filename)
				if err != nil {
					logrus.WithError(err).WithField("file", filename).Warn("Couldn't write status file")
				} else {
					defer f.Close()
				}
			case *proto.WorkloadEndpointStatusRemove:
				// Delete file from dir.
				filename := filepath.Join(fr.endpointStatusDirPrefix, m.Id.WorkloadId)
				err := os.Remove(filename)
				if err != nil {
					logrus.WithError(err).WithField("file", filename).Warn("Couldn't rm status file")
				}
			default:
				logrus.WithField("update", e).Warn("Skipping unrecognized endpoint update")
			}
		}
	}
}

// ensurePolicyStatusDir ensures there is a directory
// named "policy" with the specified path prefix.
// If truncate is true, wipes all contents from the
// existing directory.
func ensurePolicyStatusDir(prefix string, truncate bool) error {
	filename := filepath.Join(prefix, "policy")

	entries, err := os.ReadDir(filename)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return os.Mkdir(filename, 0644)
		}
		return err
	}

	if truncate {
		for _, e := range entries {
			// Remove file (and children if it's a directory).
			err := os.RemoveAll(filepath.Join(filename, e.Name()))
			if err != nil {
				return err
			}
		}
	}

	return nil
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
