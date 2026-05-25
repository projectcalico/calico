//go:build !linux

// Copyright (c) 2017-2026 Tigera, Inc. All rights reserved.
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
	"fmt"
	"os"
	"path"
	"runtime"

	"github.com/sirupsen/logrus"
)

// newFileDestination on non-Linux opens the file with a plain os.OpenFile.
// Log rotation under SIGHUP is not supported on these platforms.
func newFileDestination(
	level logrus.Level,
	filePath string,
	disableLogDropping bool,
	writeErrors Counter,
) (*destination, error) {
	if err := os.MkdirAll(path.Dir(filePath), 0755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return newStreamDestination(
		level,
		f,
		make(chan queuedLog, logQueueSize),
		disableLogDropping,
		writeErrors,
	), nil
}

// newSyslogDestinationForTag is a no-op stub. Syslog is not supported on
// non-Linux platforms.
func newSyslogDestinationForTag(
	level logrus.Level,
	tag string,
	disableLogDropping bool,
	writeErrors Counter,
) (*destination, error) {
	return nil, fmt.Errorf("syslog is not supported on %s", runtime.GOOS)
}
