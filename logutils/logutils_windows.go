// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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
	"os"
	"path"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/config"
	"github.com/projectcalico/libcalico-go/lib/logutils"
)

// File destination for Windows
func getFileDestination(configParams *config.Config, logLevel log.Level) (fileDest *logutils.Destination, fileDirErr error, fileOpenErr error) {
	fileDirErr = os.MkdirAll(path.Dir(configParams.LogFilePath), 0755)
	var logFile io.Writer
	logFile, fileOpenErr = openLogFile(configParams.LogFilePath, 0644)
	if fileDirErr == nil && fileOpenErr == nil {
		fileDest = logutils.NewStreamDestination(
			logLevel,
			logFile,
			make(chan logutils.QueuedLog, logQueueSize),
			configParams.DebugDisableLogDropping,
			counterLogErrors,
		)
	}
	return
}

// Stub, syslog destination is not used on Windows
func getSyslogDestination(configParams *config.Config, logLevel log.Level) (*logutils.Destination, error) {
	return nil, nil
}

// Stub, this func is not used on Windows
func DumpHeapMemoryOnSignal(configParams *config.Config) {
	return
}

// A simple io.Writer for logging to file
type FileWriter struct {
	file *os.File
}

func (f *FileWriter) Write(p []byte) (int, error) {
	return f.file.Write(p)
}

func openLogFile(path string, mode os.FileMode) (*FileWriter, error) {
	var w FileWriter
	var err error
	w.file, err = os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, mode)
	if err != nil {
		return nil, err
	}
	return &w, err
}
