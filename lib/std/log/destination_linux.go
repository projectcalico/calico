//go:build linux

// Copyright (c) 2016-2026 Tigera, Inc. All rights reserved.
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

package log

import (
	"log/syslog"
	"os"
	"path"

	"github.com/sirupsen/logrus"
)

// newFileDestination opens a rotation-aware writer at the given path and
// returns a destination that writes to it. The parent directory is created
// if needed.
func newFileDestination(
	level logrus.Level,
	filePath string,
	disableLogDropping bool,
	writeErrors Counter,
) (*destination, error) {
	if err := os.MkdirAll(path.Dir(filePath), 0755); err != nil {
		return nil, err
	}
	w, err := newRotatingFile(filePath, 0644)
	if err != nil {
		return nil, err
	}
	return newStreamDestination(
		level,
		w,
		make(chan queuedLog, logQueueSize),
		disableLogDropping,
		writeErrors,
	), nil
}

// newSyslogDestinationForTag connects to the system syslog daemon with the
// given tag and returns a destination that writes to it.
func newSyslogDestinationForTag(
	level logrus.Level,
	tag string,
	disableLogDropping bool,
	writeErrors Counter,
) (*destination, error) {
	// LOG_USER facility; severity is overridden per-log by writeToSyslog.
	priority := syslog.LOG_USER | syslog.LOG_INFO
	w, err := syslog.Dial("", "", priority, tag)
	if err != nil {
		return nil, err
	}
	return newSyslogDestination(
		level,
		w,
		make(chan queuedLog, logQueueSize),
		disableLogDropping,
		writeErrors,
	), nil
}
