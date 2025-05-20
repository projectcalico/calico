// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package log

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// AppendTime appends a time to the buffer in our format
// "2006-01-02 15:04:05.000".
func AppendTime(b *bytes.Buffer, t time.Time) {
	// Want "2006-01-02 15:04:05.000" but the formatter has an optimised
	// impl of RFC3339Nano, which we can easily tweak into our format.
	b.Grow(timeFormatLen)
	buf := b.AvailableBuffer()
	buf = t.AppendFormat(buf, time.RFC3339Nano)
	buf = buf[:timeFormatLen]
	const tPos = len("2006-01-02T") - 1
	buf[tPos] = ' '
	const dotPos = len("2006-01-02T15:04:05.") - 1

	// RFC3339Nano truncates the fractional seconds if zero, put the dot in
	// place if it isn't already and overwrite any non-digit characters with
	// zeros to replace the timezone or 'Z' that RFC3339Nano might have added.
	overwrite := false
	if buf[dotPos] != '.' {
		buf[dotPos] = '.'
		overwrite = true
	}
	for i := dotPos + 1; i < len(buf); i++ {
		if overwrite || buf[i] < '0' || buf[i] > '9' {
			buf[i] = '0'
			overwrite = true
		}
	}
	_, _ = b.Write(buf)
}

// TestingTWriter adapts a *testing.T as a Writer so it can be used as a target
// for logrus.  typically, it should be used via the ConfigureLoggingForTestingT
// helper.
type TestingTWriter struct {
	T *testing.T
}

func (l TestingTWriter) Write(p []byte) (n int, err error) {
	l.T.Helper()
	l.T.Log(strings.TrimRight(string(p), "\r\n"))
	return len(p), nil
}

// ConfigureEarlyLogging installs our logging adapters and enables early logging to screen
// if it is enabled by either the <envPrefix>_EARLYLOGSEVERITYSCREEN or <envPrefix>_LOGSEVERITYSCREEN
// environment variable.
func ConfigureEarlyLogging(formatterName, envPrefix string) {
	// Log to stdout.  This prevents fluentd, for example, from interpreting all our logs as errors by default.
	SetOutput(os.Stdout)

	// Set up logging formatting.
	ConfigureFormatter(formatterName)

	envPrefix = strings.ToUpper(envPrefix)

	// First try the early-only environment variable.  Since the normal
	// config processing doesn't know about that variable, normal config
	// will override it once it's loaded.
	rawLogLevel := os.Getenv(fmt.Sprintf("%s_EARLYLOGSEVERITYSCREEN", envPrefix))
	if rawLogLevel == "" {
		// Early-only flag not set, look for the normal config-owned
		// variable.
		rawLogLevel = os.Getenv(fmt.Sprintf("%s_LOGSEVERITYSCREEN", envPrefix))
	}

	// Default to logging errors.
	logLevelScreen := ErrorLevel
	if rawLogLevel != "" {
		parsedLevel, err := ParseLevel(rawLogLevel)
		if err == nil {
			logLevelScreen = parsedLevel
		} else {
			WithError(err).Error("Failed to parse early log level, defaulting to error.")
		}
	}
	SetLevel(logLevelScreen)
	Infof("Early screen log level set to %v", logLevelScreen)
}
