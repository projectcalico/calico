// Copyright (c) 2016-2025 Tigera, Inc. All rights reserved.
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

package daemon

import (
	"os"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/lib/logrusr"
)

var (
	counterDroppedLogs = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_logs_dropped",
		Help: "Number of logs dropped because the output stream was blocked.",
	})
	counterLogErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_log_errors",
		Help: "Number of errors encountered while logging.",
	})
)

func init() {
	prometheus.MustRegister(
		counterDroppedLogs,
		counterLogErrors,
	)
}

const logQueueSize = 100

// ConfigureLogging uses the resolved configuration to complete the logging
// configuration.  It creates hooks for the relevant logging targets and
// attaches them to logrus.
func ConfigureLogging(configParams *config.Config) {
	// Parse the log levels, defaulting to panic if in doubt.
	logLevelScreen := logrusr.SafeParseLogLevel(configParams.LogSeverityScreen)
	logLevelFile := logrusr.SafeParseLogLevel(configParams.LogSeverityFile)
	logLevelSyslog := logrusr.SafeParseLogLevel(configParams.LogSeveritySys)

	// Work out the most verbose level that is being logged.
	mostVerboseLevel := max(logLevelFile, logLevelScreen)
	mostVerboseLevel = max(logLevelSyslog, mostVerboseLevel)

	// Disable all more-verbose levels using the global setting, this ensures that debug logs
	// are filtered out as early as possible.
	log.SetLevel(mostVerboseLevel)

	// Screen target.
	var dests []*logrusr.Destination
	if configParams.LogSeverityScreen != "" {
		dests = append(dests, getScreenDestination(configParams, logLevelScreen))
	}

	// File target.  We record any errors so we can log them out below after finishing set-up
	// of the logger.
	var fileDirErr, fileOpenErr error
	if configParams.LogSeverityFile != "" && configParams.LogFilePath != "" {
		var destination *logrusr.Destination
		destination, fileDirErr, fileOpenErr = getFileDestination(configParams, logLevelFile)
		if fileDirErr == nil && fileOpenErr == nil && destination != nil {
			dests = append(dests, destination)
		}
	}

	// Syslog target.  Again, we record the error if we fail to connect to syslog.
	var sysErr error
	if configParams.LogSeveritySys != "" {
		var destination *logrusr.Destination
		destination, sysErr = getSyslogDestination(configParams, logLevelSyslog)
		if sysErr == nil && destination != nil {
			dests = append(dests, destination)
		}
	}

	hook := logrusr.NewBackgroundHook(
		logrusr.FilterLevels(mostVerboseLevel),
		logLevelSyslog,
		dests,
		counterDroppedLogs,
		logrusr.WithDebugFileRegexp(configParams.LogDebugFilenameRegex),
	)
	hook.Start()
	log.AddHook(hook)

	// Disable logrus' default output, which only supports a single destination.  We use the
	// hook above to fan out logs to multiple destinations.
	log.SetOutput(&logrusr.NullWriter{})

	// Do any deferred error logging.
	if fileDirErr != nil {
		log.WithError(fileDirErr).WithField("file", configParams.LogFilePath).
			Fatal("Failed to create log file directory.")
	}
	if fileOpenErr != nil {
		log.WithError(fileOpenErr).WithField("file", configParams.LogFilePath).
			Fatal("Failed to open log file.")
	}
	if sysErr != nil {
		// We don't bail out if we can't connect to syslog because our default is to try to
		// connect but it's very common for syslog to be disabled when we're run in a
		// container.
		log.WithError(sysErr).Error(
			"Failed to connect to syslog. To prevent this error, either set config " +
				"parameter LogSeveritySys=none or configure a local syslog service.")
	}
}

func getScreenDestination(configParams *config.Config, logLevel log.Level) *logrusr.Destination {
	return logrusr.NewStreamDestination(
		logLevel,
		os.Stdout,
		make(chan logrusr.QueuedLog, logQueueSize),
		configParams.DebugDisableLogDropping,
		counterLogErrors,
	)
}
