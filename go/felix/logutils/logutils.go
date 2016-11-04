// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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
	"bytes"
	"fmt"
	log "github.com/Sirupsen/logrus"
	logrus_syslog "github.com/Sirupsen/logrus/hooks/syslog"
	"github.com/mipearson/rfw"
	"github.com/projectcalico/felix/go/felix/config"
	"io"
	"log/syslog"
	"os"
	"path"
	"runtime"
	"sort"
	"strings"
	"sync"
)

// logrusToSyslogLevel maps logrus.Level to the matching syslog level used by
// the syslog hook.  The syslog hook does filtering after doing the same
// conversion so we need to give it a syslog level.
var logrusToSyslogLevel = map[log.Level]syslog.Priority{
	log.DebugLevel: syslog.LOG_DEBUG,
	log.InfoLevel:  syslog.LOG_INFO,
	log.WarnLevel:  syslog.LOG_WARNING,
	log.ErrorLevel: syslog.LOG_ERR,
	log.FatalLevel: syslog.LOG_CRIT,
	log.PanicLevel: syslog.LOG_CRIT,
}

// ConfigureEarlyLogging installs our logging adapters, and enables early logging to stderr
// if it is enabled by either the FELIX_EARLYLOGSEVERITYSCREEN or FELIX_LOGSEVERITYSCREEN
// environment variable.
func ConfigureEarlyLogging() {
	// Replace logrus' formatter with a custom one using our time format,
	// shared with the Python code.
	log.SetFormatter(&Formatter{})

	// Install a hook that adds file/line no information.
	log.AddHook(&ContextHook{})

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
	logLevelScreen := safeParseLogLevel(configParams.LogSeverityScreen)
	logLevelFile := safeParseLogLevel(configParams.LogSeverityFile)
	logLevelSyslog := safeParseLogLevel(configParams.LogSeveritySys)

	// Work out the most verbose level that is being logged.
	mostVerboseLevel := logLevelScreen
	if logLevelFile > mostVerboseLevel {
		mostVerboseLevel = logLevelFile
	}
	if logLevelSyslog > mostVerboseLevel {
		mostVerboseLevel = logLevelScreen
	}
	// Disable all more-verbose levels using the global setting, this
	// ensures that debug logs are filtered as early as possible in the
	// pipeline.
	log.SetLevel(mostVerboseLevel)

	// Disable logrus' default output, which only supports a single
	// destination at the global log level.
	log.SetOutput(&NullWriter{})

	// Screen target.
	if configParams.LogSeverityScreen != "" {
		screenLevels := filterLevels(logLevelScreen)
		log.AddHook(&StreamHook{
			writer: os.Stdout,
			levels: screenLevels,
		})
	}

	// File target.
	if configParams.LogSeverityFile != "" {
		fileLevels := filterLevels(logLevelFile)
		if err := os.MkdirAll(path.Dir(configParams.LogFilePath), 0755); err != nil {
			log.WithError(err).Fatal("Failed to create log dir")
		}
		rotAwareFile, err := rfw.Open(configParams.LogFilePath, 0644)
		if err != nil {
			log.WithError(err).Fatal("Failed to open log file")
		}
		log.AddHook(&StreamHook{
			writer: rotAwareFile,
			levels: fileLevels,
		})
	}

	if configParams.LogSeveritySys != "" {
		// Syslog target.
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
		if hook, err := logrus_syslog.NewSyslogHook(net, addr, priority, tag); err != nil {
			log.WithError(err).WithField("level", configParams.LogSeveritySys).Error("Failed to connect to syslog")
		} else {
			syslogLevels := filterLevels(logLevelSyslog)
			levHook := &LeveledHook{
				hook:   hook,
				levels: syslogLevels,
			}
			log.AddHook(levHook)
		}
	}
}

// filterLevels returns all the logrus.Level values <= maxLevel.
func filterLevels(maxLevel log.Level) []log.Level {
	levels := []log.Level{}
	for _, l := range log.AllLevels {
		if l <= maxLevel {
			levels = append(levels, l)
		}
	}
	return levels
}

// Formatter is our custom log formatter, which mimics the style used by the
// Python version of Felix.  In particular, it uses a sortable timestamp and
// logs the level and PID.  Since logrus deosn't yet expose file and line
// numbers, we log "go" as a placeholder.
//
//    2016-10-04 14:45:45,999 [ERROR][70826] go: Hello world key=value
type Formatter struct{}

func (f *Formatter) Format(entry *log.Entry) ([]byte, error) {
	// Sort the keys for consistent output.
	var keys []string = make([]string, 0, len(entry.Data))
	for k := range entry.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	b := &bytes.Buffer{}

	stamp := entry.Time.Format("2006-01-02 15:04:05.000")
	levelStr := strings.ToUpper(entry.Level.String())
	pid := os.Getpid()
	fileName := entry.Data["file"]
	lineNo := entry.Data["line"]
	formatted := fmt.Sprintf("%s [%s][%d] %v %v: %v",
		stamp, levelStr, pid, fileName, lineNo, entry.Message)
	b.WriteString(formatted)

	for _, key := range keys {
		if key == "file" || key == "line" {
			continue
		}
		b.WriteString(fmt.Sprintf(" %v=%v", key, entry.Data[key]))
	}

	b.WriteByte('\n')
	return b.Bytes(), nil
}

// NullWriter is a dummy writer that always succeeds and does nothing.
type NullWriter struct{}

func (w *NullWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

type ContextHook struct {
}

func (hook ContextHook) Levels() []log.Level {
	return log.AllLevels
}

func (hook ContextHook) Fire(entry *log.Entry) error {
	pcs := make([]uintptr, 4)
	if numEntries := runtime.Callers(6, pcs); numEntries > 0 {
		frames := runtime.CallersFrames(pcs)
		for {
			frame, more := frames.Next()
			if !shouldSkipFrame(frame) {
				entry.Data["file"] = path.Base(frame.File)
				entry.Data["line"] = frame.Line
				break
			}
			if !more {
				break
			}
		}
	}
	return nil
}

func shouldSkipFrame(frame runtime.Frame) bool {
	return strings.LastIndex(frame.File, "exported.go") > 0 ||
		strings.LastIndex(frame.File, "logger.go") > 0 ||
		strings.LastIndex(frame.File, "entry.go") > 0
}

// StreamHook is a logrus Hook that writes to a stream when fired.
// It supports configuration of log levels at which is fires.
type StreamHook struct {
	mu     sync.Mutex
	writer io.Writer
	levels []log.Level
}

func (h *StreamHook) Levels() []log.Level {
	return h.levels
}

func (h *StreamHook) Fire(entry *log.Entry) (err error) {
	var reader io.Reader
	if reader, err = entry.Reader(); err != nil {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	_, err = io.Copy(h.writer, reader)
	return
}

type LeveledHook struct {
	hook   log.Hook
	levels []log.Level
}

func (h *LeveledHook) Levels() []log.Level {
	return h.levels
}

func (h *LeveledHook) Fire(entry *log.Entry) error {
	return h.hook.Fire(entry)
}

// safeParseLogLevel parses a string version of a logrus log level, defaulting
// to logrus.PanicLevel on failure.
func safeParseLogLevel(logLevel string) log.Level {
	defaultedLevel := log.PanicLevel
	if logLevel != "" {
		parsedLevel, err := log.ParseLevel(logLevel)
		if err == nil {
			defaultedLevel = parsedLevel
		} else {
			log.WithField("raw level", logLevel).Warn(
				"Invalid log level, defaulting to panic")
		}
	}
	return defaultedLevel
}
