// Copyright (c) 2023 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package handlemgr

import (
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/netlinkshim"
)

const (
	maxConnFailures      = 3
	defaultSocketTimeout = 10 * time.Second
)

type HandleManager struct {
	// Current netlink handle, or nil if we need to reconnect.
	cachedHandle         netlinkshim.Interface
	reopenHandleNextTime bool
	// numRepeatFailures counts the number of repeated netlink connection failures.
	// reset on successful connection.
	numRepeatFailures int

	strictEnabled bool
	socketTimeout time.Duration

	featureDetector  environment.FeatureDetectorIface
	newNetlinkHandle func() (netlinkshim.Interface, error)
}

type NetlinkHandleManagerOpt func(*HandleManager)

func WithSocketTimeout(d time.Duration) NetlinkHandleManagerOpt {
	return func(manager *HandleManager) {
		manager.socketTimeout = d
	}
}

func WithNewHandleOverride(newNetlinkHandle func() (netlinkshim.Interface, error)) NetlinkHandleManagerOpt {
	return func(manager *HandleManager) {
		manager.newNetlinkHandle = newNetlinkHandle
	}
}

func WithStrictModeOverride(strictEnabled bool) NetlinkHandleManagerOpt {
	return func(manager *HandleManager) {
		manager.strictEnabled = strictEnabled
	}
}

func NewHandleManager(featureDetector environment.FeatureDetectorIface, opts ...NetlinkHandleManagerOpt) *HandleManager {
	nlm := &HandleManager{
		socketTimeout:    defaultSocketTimeout,
		featureDetector:  featureDetector,
		newNetlinkHandle: netlinkshim.NewRealNetlink,
		strictEnabled:    true,
	}
	for _, o := range opts {
		o(nlm)
	}
	return nlm
}

// Handle returns the cached netlink handle, initialising it if needed.
func (r *HandleManager) Handle() (netlinkshim.Interface, error) {
	if r.reopenHandleNextTime && r.cachedHandle != nil {
		r.cachedHandle.Delete()
		r.cachedHandle = nil
	}
	r.reopenHandleNextTime = false

	if r.cachedHandle == nil {
		nlHandle, err := r.newHandle()
		if err != nil {
			return nil, err
		}
		r.cachedHandle = nlHandle
	}
	if r.numRepeatFailures > 0 {
		logrus.WithField("numFailures", r.numRepeatFailures).Info(
			"Connected to netlink after previous failures.")
		r.numRepeatFailures = 0
	}
	return r.cachedHandle, nil
}

func (r *HandleManager) newHandle() (netlinkshim.Interface, error) {
	if r.numRepeatFailures >= maxConnFailures {
		logrus.WithField("numFailures", r.numRepeatFailures).Panic(
			"Repeatedly failed to connect to netlink.")
	}
	logrus.Debug("Trying to connect to netlink")
	nlHandle, err := r.newNetlinkHandle()
	if err != nil {
		r.numRepeatFailures++
		logrus.WithError(err).WithField("numFailures", r.numRepeatFailures).Error(
			"Failed to connect to netlink")
		return nil, err
	}
	err = nlHandle.SetSocketTimeout(r.socketTimeout)
	if err != nil {
		r.numRepeatFailures++
		logrus.WithError(err).WithField("numFailures", r.numRepeatFailures).Error(
			"Failed to set netlink timeout")
		nlHandle.Delete()
		return nil, err
	}
	if r.strictEnabled && r.featureDetector.GetFeatures().KernelSideRouteFiltering {
		logrus.Debug("Kernel supports route filtering, enabling 'strict' netlink mode.")
		err = nlHandle.SetStrictCheck(true)
		if err != nil {
			r.numRepeatFailures++
			logrus.WithError(err).WithField("numFailures", r.numRepeatFailures).Error(
				"Failed to set netlink strict mode")
			nlHandle.Delete()
			return nil, err
		}
	}
	return nlHandle, nil
}

// MarkHandleForReopen ensures that the next call to Handle() will open a
// fresh handle.  The current handle is not closed immediately, it will be
// closed when the new handle is opened.
//
// We used to close the handle immediately but that led to bugs where the
// caller wouldn't refresh its handle until the next time around its loop.
func (r *HandleManager) MarkHandleForReopen() {
	r.reopenHandleNextTime = true
}
