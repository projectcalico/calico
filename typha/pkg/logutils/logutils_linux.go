// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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

package logutils

import (
	"io"
	"log/syslog"
	"os"
	"path"

	"github.com/mipearson/rfw"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/typha/pkg/config"
)

func getFileDestination(configParams *config.Config, logLevel log.Level) (fileDest *logutils.Destination, fileDirErr error, fileOpenErr error) {
	fileDirErr = os.MkdirAll(path.Dir(configParams.LogFilePath), 0755)
	var rotAwareFile io.Writer
	rotAwareFile, fileOpenErr = rfw.Open(configParams.LogFilePath, 0644)
	if fileDirErr == nil && fileOpenErr == nil {
		fileDest = logutils.NewStreamDestination(
			logLevel,
			rotAwareFile,
			make(chan logutils.QueuedLog, logQueueSize),
			configParams.DebugDisableLogDropping,
			counterLogErrors,
		)
	}
	return
}

func getSyslogDestination(configParams *config.Config, logLevel log.Level) (*logutils.Destination, error) {
	// Set net/addr to "" so we connect to the system syslog server rather
	// than a remote one.
	net := ""
	addr := ""
	// The priority parameter is a combination of facility and default
	// severity.  We want to log with the standard LOG_USER facility; the
	// severity is actually irrelevant because the hook always overrides
	// it.
	priority := syslog.LOG_USER | syslog.LOG_INFO
	tag := "calico-typha"
	w, sysErr := syslog.Dial(net, addr, priority, tag)
	if sysErr == nil {
		syslogDest := logutils.NewSyslogDestination(
			logLevel,
			w,
			make(chan logutils.QueuedLog, logQueueSize),
			configParams.DebugDisableLogDropping,
			counterLogErrors,
		)
		return syslogDest, sysErr
	}
	return nil, sysErr
}
