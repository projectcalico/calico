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
	"fmt"
	"io"
	"regexp"
	"sync"

	"github.com/sirupsen/logrus"
)

// All types in this file are internal. The public surface for configuration
// is Configure(Options); these types implement the background fanout
// described there.

const logQueueSize = 100

// nullWriter discards everything. Used to disable logrus's default single
// output once we install the background hook for multi-destination fanout.
type nullWriter struct{}

func (w *nullWriter) Write(p []byte) (int, error) { return len(p), nil }

// queuedLog is the envelope passed from the foreground hook to background
// destination goroutines.
type queuedLog struct {
	Level         logrus.Level
	Message       []byte
	SyslogMessage string
	WaitGroup     *sync.WaitGroup
	// NumSkippedLogs is set when the destination's channel was full and one
	// or more logs ahead of this one were dropped.
	NumSkippedLogs uint
}

func (ql queuedLog) onLogDone() {
	if ql.WaitGroup != nil {
		ql.WaitGroup.Done()
	}
}

// destination is a single log output target: a channel + a level filter +
// a writer function. Logs are dispatched into the channel by the foreground
// hook and pulled by a background goroutine running loopWritingLogs.
type destination struct {
	level    logrus.Level
	channel  chan queuedLog
	writeLog func(ql queuedLog) error

	// disableLogDropping forces all logs to be queued even if the channel
	// is full. Trades latency for completeness.
	disableLogDropping bool

	// lock protects numDroppedLogs.
	lock           sync.Mutex
	numDroppedLogs uint

	// writeErrors is incremented when writeLog returns an error.
	writeErrors Counter
}

func newStreamDestination(
	level logrus.Level,
	writer io.Writer,
	c chan queuedLog,
	disableLogDropping bool,
	writeErrors Counter,
) *destination {
	return &destination{
		level:              level,
		channel:            c,
		disableLogDropping: disableLogDropping,
		writeErrors:        writeErrors,
		writeLog: func(ql queuedLog) error {
			if ql.NumSkippedLogs > 0 {
				_, _ = fmt.Fprintf(writer, "... dropped %d logs ...\n", ql.NumSkippedLogs)
			}
			_, err := writer.Write(ql.Message)
			return err
		},
	}
}

func newSyslogDestination(
	level logrus.Level,
	writer syslogWriter,
	c chan queuedLog,
	disableLogDropping bool,
	writeErrors Counter,
) *destination {
	return &destination{
		level:              level,
		channel:            c,
		disableLogDropping: disableLogDropping,
		writeErrors:        writeErrors,
		writeLog: func(ql queuedLog) error {
			if ql.NumSkippedLogs > 0 {
				_ = writer.Warning(fmt.Sprintf("... dropped %d logs ...\n", ql.NumSkippedLogs))
			}
			return writeToSyslog(writer, ql)
		},
	}
}

// send enqueues a log. Returns true on success, false if the channel was full
// and the log was dropped (unless disableLogDropping is set, in which case it
// blocks until the channel accepts the message).
func (d *destination) send(ql queuedLog) (ok bool) {
	if d.disableLogDropping {
		d.channel <- ql
		return true
	}

	d.lock.Lock()
	ql.NumSkippedLogs = d.numDroppedLogs
	select {
	case d.channel <- ql:
		d.numDroppedLogs = 0
		ok = true
	default:
		d.numDroppedLogs++
	}
	d.lock.Unlock()
	return
}

// loopWritingLogs is the background goroutine for a destination.
func (d *destination) loopWritingLogs() {
	for ql := range d.channel {
		if err := d.writeLog(ql); err != nil && d.writeErrors != nil {
			d.writeErrors.Inc()
		}
		ql.onLogDone()
	}
}

// syslogWriter is the subset of *syslog.Writer that we depend on. Allows
// platforms without syslog (Windows) to compile with a stub.
type syslogWriter interface {
	Debug(m string) error
	Info(m string) error
	Warning(m string) error
	Err(m string) error
	Crit(m string) error
}

func writeToSyslog(writer syslogWriter, ql queuedLog) error {
	switch ql.Level {
	case logrus.PanicLevel, logrus.FatalLevel:
		return writer.Crit(ql.SyslogMessage)
	case logrus.ErrorLevel:
		return writer.Err(ql.SyslogMessage)
	case logrus.WarnLevel:
		return writer.Warning(ql.SyslogMessage)
	case logrus.InfoLevel:
		return writer.Info(ql.SyslogMessage)
	case logrus.DebugLevel:
		return writer.Debug(ql.SyslogMessage)
	}
	return nil
}

// backgroundHook is the logrus hook that (synchronously) formats each entry
// and pushes it to one or more destinations for writing on a background
// thread. The synchronous formatting and per-destination level filtering are
// preserved from libcalico-go/lib/logutils.
type backgroundHook struct {
	levels          []logrus.Level
	syslogLevel     logrus.Level
	debugFileNameRE *regexp.Regexp
	destinations    []*destination
	component       string

	// dropped is incremented for each destination that dropped a log.
	dropped Counter
}

func newBackgroundHook(
	levels []logrus.Level,
	syslogLevel logrus.Level,
	component string,
	destinations []*destination,
	debugFileNameRE *regexp.Regexp,
	dropped Counter,
) *backgroundHook {
	return &backgroundHook{
		levels:          levels,
		syslogLevel:     syslogLevel,
		component:       component,
		destinations:    destinations,
		debugFileNameRE: debugFileNameRE,
		dropped:         dropped,
	}
}

func (h *backgroundHook) Levels() []logrus.Level { return h.levels }

func (h *backgroundHook) Fire(entry *logrus.Entry) (err error) {
	if entry.Buffer != nil {
		defer entry.Buffer.Truncate(0)
	}

	if entry.Level >= logrus.DebugLevel && h.debugFileNameRE != nil {
		var file string
		if entry.Caller != nil {
			file = baseName(entry.Caller.File)
		} else if frame := findUserCaller(); frame != nil {
			file = baseName(frame.File)
		}
		if file == "" || !h.debugFileNameRE.MatchString(file) {
			return nil
		}
	}

	var serialized []byte
	if serialized, err = entry.Logger.Formatter.Format(entry); err != nil {
		return
	}

	// entry's buffer is reused; copy before sending across the channel.
	bufCopy := make([]byte, len(serialized))
	copy(bufCopy, serialized)

	ql := queuedLog{
		Level:   entry.Level,
		Message: bufCopy,
	}

	if entry.Level <= h.syslogLevel {
		ql.SyslogMessage = formatForSyslog(entry, componentFromEntry(entry, h.component))
	}

	var waitGroup *sync.WaitGroup
	if entry.Level <= logrus.FatalLevel || entry.Data[fieldForceFlush] == true {
		waitGroup = &sync.WaitGroup{}
		ql.WaitGroup = waitGroup
	}

	for _, dest := range h.destinations {
		if ql.Level > dest.level {
			continue
		}
		if waitGroup != nil {
			// Add before send: the goroutine may schedule and call Done
			// before we return from the send.
			waitGroup.Add(1)
		}
		if ok := dest.send(ql); !ok {
			if waitGroup != nil {
				waitGroup.Done()
			}
			if h.dropped != nil {
				h.dropped.Inc()
			}
		}
	}
	if waitGroup != nil {
		waitGroup.Wait()
	}
	return
}

func (h *backgroundHook) start() {
	for _, d := range h.destinations {
		go d.loopWritingLogs()
	}
}

func componentFromEntry(entry *logrus.Entry, fallback string) string {
	if c, ok := entry.Data[fieldComponent].(string); ok && c != "" {
		return c
	}
	return fallback
}

// baseName returns the file basename without using path.Base, to avoid the
// path package in the hot path.
func baseName(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}

// filterLevels returns all logrus levels ≤ maxLevel.
func filterLevels(maxLevel logrus.Level) []logrus.Level {
	out := make([]logrus.Level, 0, len(logrus.AllLevels))
	for _, l := range logrus.AllLevels {
		if l <= maxLevel {
			out = append(out, l)
		}
	}
	return out
}
