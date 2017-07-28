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
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/config"
	"github.com/projectcalico/libcalico-go/lib/logutils"
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

// ConfigureEarlyLogging installs our logging adapters, and enables early logging to screen
// if it is enabled by either the FELIX_EARLYLOGSEVERITYSCREEN or FELIX_LOGSEVERITYSCREEN
// environment variable.
func ConfigureEarlyLogging() {
	// Replace logrus' formatter with a custom one using our time format,
	// shared with the Python code.
	log.SetFormatter(&logutils.Formatter{})

	// Install a hook that adds file/line no information.
	log.AddHook(&logutils.ContextHook{})

	// First try the early-only environment variable.  Since the normal
	// config processing doesn't know about that variable, normal config
	// will override it once it's loaded.
	rawLogLevel := os.Getenv("FELIX_EARLYLOGSEVERITYSCREEN")
	if rawLogLevel == "" {
		// Early-only flag not set, look for the normal config-owned
		// variable.
		rawLogLevel = os.Getenv("FELIX_LOGSEVERITYSCREEN")
	}

	// Default to logging errors.
	logLevelScreen := log.ErrorLevel
	if rawLogLevel != "" {
		parsedLevel, err := log.ParseLevel(rawLogLevel)
		if err == nil {
			logLevelScreen = parsedLevel
		} else {
			log.WithError(err).Error("Failed to parse early log level, defaulting to error.")
		}
	}
	log.SetLevel(logLevelScreen)
	log.Infof("Early screen log level set to %v", logLevelScreen)
}

// ConfigureLogging uses the resolved configuration to complete the logging
// configuration.  It creates hooks for the relevant logging targets and
// attaches them to logrus.
func ConfigureLogging(configParams *config.Config) {
	// Parse the log levels, defaulting to panic if in doubt.
	logLevelScreen := logutils.SafeParseLogLevel(configParams.LogSeverityScreen)
	logLevelFile := logutils.SafeParseLogLevel(configParams.LogSeverityFile)
	logLevelSyslog := logutils.SafeParseLogLevel(configParams.LogSeveritySys)

	// Work out the most verbose level that is being logged.
	mostVerboseLevel := logLevelScreen
	if logLevelFile > mostVerboseLevel {
		mostVerboseLevel = logLevelFile
	}
	if logLevelSyslog > mostVerboseLevel {
		mostVerboseLevel = logLevelScreen
	}
	// Disable all more-verbose levels using the global setting, this ensures that debug logs
	// are filtered out as early as possible.
	log.SetLevel(mostVerboseLevel)

	// Screen target.
	var dests []*logutils.Destination
	if configParams.LogSeverityScreen != "" {
		screenDest := logutils.NewStreamDestination(
			logLevelScreen,
			os.Stderr,
			make(chan logutils.QueuedLog, logQueueSize),
			configParams.DebugDisableLogDropping,
			counterLogErrors,
		)
		dests = append(dests, screenDest)
	}

	// File target.  We record any errors so we can log them out below after finishing set-up
	// of the logger.
	var fileDirErr, fileOpenErr error
	if configParams.LogSeverityFile != "" && configParams.LogFilePath != "" {
		fileDirErr = os.MkdirAll(path.Dir(configParams.LogFilePath), 0755)
		var rotAwareFile io.Writer
		rotAwareFile, fileOpenErr = rfw.Open(configParams.LogFilePath, 0644)
		if fileDirErr == nil && fileOpenErr == nil {
			fileDest := logutils.NewStreamDestination(
				logLevelFile,
				rotAwareFile,
				make(chan logutils.QueuedLog, logQueueSize),
				configParams.DebugDisableLogDropping,
				counterLogErrors,
			)
			dests = append(dests, fileDest)
		}
	}

	// Syslog target.  Again, we record the error if we fail to connect to syslog.
	var sysErr error
	if configParams.LogSeveritySys != "" {
		// Set net/addr to "" so we connect to the system syslog server rather
		// than a remote one.
		net := ""
		addr := ""
		// The priority parameter is a combination of facility and default
		// severity.  We want to log with the standard LOG_USER facility; the
		// severity is actually irrelevant because the hook always overrides
		// it.
		priority := syslog.LOG_USER | syslog.LOG_INFO
		tag := "calico-felix"
		w, sysErr := syslog.Dial(net, addr, priority, tag)
		if sysErr == nil {
			syslogDest := logutils.NewSyslogDestination(
				logLevelSyslog,
				w,
				make(chan logutils.QueuedLog, logQueueSize),
				configParams.DebugDisableLogDropping,
				counterLogErrors,
			)
			dests = append(dests, syslogDest)
		}
	}

	hook := logutils.NewBackgroundHook(logutils.FilterLevels(mostVerboseLevel), logLevelSyslog, dests, counterDroppedLogs)
	hook.Start()
	log.AddHook(hook)

	// Disable logrus' default output, which only supports a single destination.  We use the
	// hook above to fan out logs to multiple destinations.
	log.SetOutput(&logutils.NullWriter{})

	// Since we push our logs onto a second thread via a channel, we can disable the
	// Logger's built-in mutex completely.
	log.StandardLogger().SetNoLock()

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
