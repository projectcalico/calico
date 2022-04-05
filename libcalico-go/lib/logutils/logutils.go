// Copyright (c) 2016-2019,2021 Tigera, Inc. All rights reserved.
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
	"io"
	"os"
	"path"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

const (
	// FieldForceFlush is a field name used to signal to the BackgroundHook that it should flush the log after this
	// message.  It can be used as follows: logrus.WithField(FieldForceFlush, true).Info("...")
	FieldForceFlush = "__flush__"

	// fieldFileName is a reserved field name used to pass the filename from the ContextHook to our Formatter.
	fieldFileName = "__file__"
	// fieldLineNumber is a reserved field name used to pass the line number from the ContextHook to our Formatter.
	fieldLineNumber = "__line__"
)

// FilterLevels returns all the logrus.Level values <= maxLevel.
func FilterLevels(maxLevel log.Level) []log.Level {
	levels := []log.Level{}
	for _, l := range log.AllLevels {
		if l <= maxLevel {
			levels = append(levels, l)
		}
	}
	return levels
}

// Formatter is our custom log formatter designed to balance ease of machine processing
// with human readability.  Logs include:
//    - A sortable millisecond timestamp, for scanning and correlating logs
//    - The log level, near the beginning of the line, to aid in visual scanning
//    - The PID of the process to make it easier to spot log discontinuities (If
//      you are looking at two disjoint chunks of log, were they written by the
//      same process?  Was there a restart in-between?)
//    - The file name and line number, as essential context
//    - The message!
//    - Log fields appended in sorted order
//
// Example:
//    2017-01-05 09:17:48.238 [INFO][85386] endpoint_mgr.go 434: Skipping configuration of
//    interface because it is oper down. ifaceName="cali1234"
type Formatter struct {
	// If specified, prepends the component to the file name. This is useful for when
	// multiple components are logging to the same file (e.g., calico/node) for distinguishing
	// which component sourced the log.
	Component string
}

func (f *Formatter) Format(entry *log.Entry) ([]byte, error) {
	stamp := entry.Time.Format("2006-01-02 15:04:05.000")
	levelStr := strings.ToUpper(entry.Level.String())
	pid := os.Getpid()
	fileName := entry.Data[fieldFileName]
	lineNo := entry.Data[fieldLineNumber]
	b := entry.Buffer
	if b == nil {
		b = &bytes.Buffer{}
	}
	if f.Component != "" {
		fmt.Fprintf(b, "%s [%s][%d] %s/%v %v: %v", stamp, levelStr, pid, f.Component, fileName, lineNo, entry.Message)
	} else {
		fmt.Fprintf(b, "%s [%s][%d] %v %v: %v", stamp, levelStr, pid, fileName, lineNo, entry.Message)
	}
	appendKVsAndNewLine(b, entry)
	return b.Bytes(), nil
}

// FormatForSyslog formats logs in a way tailored for syslog.  It avoids logging information that is
// already included in the syslog metadata such as timestamp and PID.  The log level _is_ included
// because syslog doesn't seem to output it by default and it's very useful.
//
//    INFO endpoint_mgr.go 434: Skipping configuration of interface because it is oper down.
//    ifaceName="cali1234"
func FormatForSyslog(entry *log.Entry) string {
	levelStr := strings.ToUpper(entry.Level.String())
	fileName := entry.Data[fieldFileName]
	lineNo := entry.Data[fieldLineNumber]
	b := entry.Buffer
	if b == nil {
		b = &bytes.Buffer{}
	}
	fmt.Fprintf(b, "%s %v %v: %v", levelStr, fileName, lineNo, entry.Message)
	appendKVsAndNewLine(b, entry)
	return b.String()
}

// appendKeysAndNewLine writes the KV pairs attached to the entry to the end of the buffer, then
// finishes it with a newline.
func appendKVsAndNewLine(b *bytes.Buffer, entry *log.Entry) {
	// Sort the keys for consistent output.
	var keys []string = make([]string, 0, len(entry.Data))
	for k := range entry.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		if key == fieldFileName || key == fieldLineNumber || key == FieldForceFlush {
			continue
		}
		var value interface{} = entry.Data[key]
		var stringifiedValue string
		if err, ok := value.(error); ok {
			stringifiedValue = err.Error()
		} else if stringer, ok := value.(fmt.Stringer); ok {
			// Trust the value's String() method.
			stringifiedValue = stringer.String()
		} else {
			// No string method, use %#v to get a more thorough dump.
			fmt.Fprintf(b, " %v=%#v", key, value)
			continue
		}
		b.WriteByte(' ')
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(stringifiedValue)
	}
	b.WriteByte('\n')
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
	// We used to do runtime.Callers(6, pcs) here so that we'd skip straight to the expected
	// frame.  However, if an intermediate frame gets inlined we can skip too many frames in
	// that case.  The only safe option is to use skip=1 and then let CallersFrames() deal
	// with any inlining.
	pcs := make([]uintptr, 20)
	if numEntries := runtime.Callers(0, pcs); numEntries > 0 {
		pcs = pcs[:numEntries]
		frames := runtime.CallersFrames(pcs)
		for {
			frame, more := frames.Next()
			if !shouldSkipFrame(frame) {
				// We found the frame we were looking for.  Record its file/line number.
				entry.Data[fieldFileName] = path.Base(frame.File)
				entry.Data[fieldLineNumber] = frame.Line
				break
			}
			if !more {
				entry.Data[fieldFileName] = "filename-lookup-failed"
				entry.Data[fieldLineNumber] = -1
				break
			}
		}
	} else {
		entry.Data[fieldFileName] = "filename-lookup-failed"
		entry.Data[fieldLineNumber] = -2
	}
	return nil
}

// shouldSkipFrame returns true if the given frame belongs to the logging library (or this utility package).
// Note: this is on the critical path for every log, if you need to update it, make sure to run the
// benchmarks.
//
// Some things we've tried that were worse than strings.HasSuffix():
//
// - using a regexp:            ~100x slower
// - using strings.LastIndex(): ~10x slower
// - omitting the package:      no benefit
func shouldSkipFrame(frame runtime.Frame) bool {
	if strings.Contains(frame.File, "runtime/extern.go") {
		return true
	}
	if strings.HasSuffix(frame.File, "/hooks.go") ||
		strings.HasSuffix(frame.File, "/entry.go") ||
		strings.HasSuffix(frame.File, "/logger.go") ||
		strings.HasSuffix(frame.File, "/exported.go") {
		if strings.Contains(frame.File, "/logrus") {
			return true
		}
	}
	if strings.HasSuffix(frame.File, "/lib/logutils/logutils.go") {
		if strings.Contains(frame.File, "/libcalico-go") {
			return true
		}
	}
	if strings.HasSuffix(frame.File, "/lib/logutils/ratelimitedlogger.go") {
		if strings.Contains(frame.File, "/libcalico-go") {
			return true
		}
	}
	return false
}

type QueuedLog struct {
	Level         log.Level
	Message       []byte
	SyslogMessage string
	WaitGroup     *sync.WaitGroup

	// NumSkippedLogs contains the number of logs that were skipped before this log (due to the
	// queue being blocked).
	NumSkippedLogs uint
}

func (ql QueuedLog) OnLogDone() {
	if ql.WaitGroup != nil {
		ql.WaitGroup.Done()
	}
}

func NewStreamDestination(
	level log.Level,
	writer io.Writer,
	c chan QueuedLog,
	disableLogDropping bool,
	counter prometheus.Counter,
) *Destination {
	return &Destination{
		Level:   level,
		Channel: c,
		writeLog: func(ql QueuedLog) error {
			if ql.NumSkippedLogs > 0 {
				fmt.Fprintf(writer, "... dropped %d logs ...\n",
					ql.NumSkippedLogs)
			}
			_, err := writer.Write(ql.Message)
			return err
		},
		disableLogDropping: disableLogDropping,
		counter:            counter,
	}
}

func NewSyslogDestination(
	level log.Level,
	writer syslogWriter,
	c chan QueuedLog,
	disableLogDropping bool,
	counter prometheus.Counter,
) *Destination {
	return &Destination{
		Level:   level,
		Channel: c,
		writeLog: func(ql QueuedLog) error {
			if ql.NumSkippedLogs > 0 {
				writer.Warning(fmt.Sprintf("... dropped %d logs ...\n",
					ql.NumSkippedLogs))
			}
			err := writeToSyslog(writer, ql)
			return err
		},
		disableLogDropping: disableLogDropping,
		counter:            counter,
	}
}

type Destination struct {
	// Level is the minimum level that a log must have to be logged to this destination.
	Level log.Level
	// Channel is the channel used to queue logs to the background worker thread.  Public for
	// test purposes.
	Channel chan QueuedLog
	// WriteLog is the function to actually make a log.  The constructors above initialise this
	// with a function that logs to a stream or to syslog, for example.
	writeLog func(ql QueuedLog) error

	// DisableLogDropping forces all logs to be queued even if the destination blocks.
	disableLogDropping bool

	// Lock protects the numDroppedLogs count.
	lock           sync.Mutex
	numDroppedLogs uint

	// Counter is the prometheus counter for logged errors that this destination will increment
	counter prometheus.Counter
}

// Send sends a log to the background thread.  It returns true on success or false if the channel
// is blocked.
func (d *Destination) Send(ql QueuedLog) (ok bool) {
	if d.disableLogDropping {
		d.Channel <- ql
		ok = true
		return
	}

	d.lock.Lock()
	ql.NumSkippedLogs = d.numDroppedLogs
	select {
	case d.Channel <- ql:
		// We've now queued reporting of all the dropped logs, zero out the counter.
		d.numDroppedLogs = 0
		ok = true
	default:
		d.numDroppedLogs += 1
	}
	d.lock.Unlock()
	return
}

// LoopWritingLogs is intended to be used as a background go-routine.  It processes the logs from
// the channel.
func (d *Destination) LoopWritingLogs() {
	for ql := range d.Channel {
		err := d.writeLog(ql)
		if err != nil {
			// Increment the number of errors while trying to write to log
			d.counter.Inc()
			fmt.Fprintf(os.Stderr, "Failed to write to log: %v", err)
		}
		ql.OnLogDone()
	}
}

// Close closes the channel to the background goroutine.  This is only safe to call if you know
// that the destination is no longer in use by any thread; in tests, for example.
func (d *Destination) Close() {
	close(d.Channel)
}

type syslogWriter interface {
	Debug(m string) error
	Info(m string) error
	Warning(m string) error
	Err(m string) error
	Crit(m string) error
}

func writeToSyslog(writer syslogWriter, ql QueuedLog) error {
	switch ql.Level {
	case log.PanicLevel:
		return writer.Crit(ql.SyslogMessage)
	case log.FatalLevel:
		return writer.Crit(ql.SyslogMessage)
	case log.ErrorLevel:
		return writer.Err(ql.SyslogMessage)
	case log.WarnLevel:
		return writer.Warning(ql.SyslogMessage)
	case log.InfoLevel:
		return writer.Info(ql.SyslogMessage)
	case log.DebugLevel:
		return writer.Debug(ql.SyslogMessage)
	default:
		return nil
	}
}

// BackgroundHook is a logrus Hook that (synchronously) formats each log and sends it to one or more
// Destinations for writing on a background thread.  It supports filtering destinations on
// individual log levels.  We write logs from background threads so that blocking of the output
// stream doesn't block the mainline code.  Up to a point, we queue logs for writing, then we start
// dropping logs.
type BackgroundHook struct {
	levels          []log.Level
	syslogLevel     log.Level
	debugFileNameRE *regexp.Regexp

	destinations []*Destination

	// Our own copy of the dropped logs counter, used for logging out when we drop logs.
	// Must be read/updated using atomic.XXX.
	numDroppedLogs  uint64
	lastDropLogTime time.Duration

	// Counter
	counter prometheus.Counter
}

type BackgroundHookOpt func(hook *BackgroundHook)

func WithDebugFileRegexp(re *regexp.Regexp) BackgroundHookOpt {
	return func(hook *BackgroundHook) {
		hook.debugFileNameRE = re
	}
}

var _ = WithDebugFileRegexp

func NewBackgroundHook(
	levels []log.Level,
	syslogLevel log.Level,
	destinations []*Destination,
	counter prometheus.Counter,
	opts ...BackgroundHookOpt,
) *BackgroundHook {
	bh := &BackgroundHook{
		destinations: destinations,
		levels:       levels,
		syslogLevel:  syslogLevel,
		counter:      counter,
	}
	for _, opt := range opts {
		opt(bh)
	}
	return bh
}

func (h *BackgroundHook) Levels() []log.Level {
	return h.levels
}

func (h *BackgroundHook) Fire(entry *log.Entry) (err error) {
	if entry.Buffer != nil {
		defer entry.Buffer.Truncate(0)
	}

	if entry.Level >= log.DebugLevel && h.debugFileNameRE != nil {
		// This is a debug log, check if debug logging is enabled for this file.
		if fileName, ok := entry.Data[fieldFileName]; !ok || !h.debugFileNameRE.MatchString(fileName.(string)) {
			return nil
		}
	}

	var serialized []byte
	if serialized, err = entry.Logger.Formatter.Format(entry); err != nil {
		return
	}

	// entry's buffer will be reused after we return but we're about to send the message over
	// a channel so we need to take a copy.
	bufCopy := make([]byte, len(serialized))
	copy(bufCopy, serialized)

	ql := QueuedLog{
		Level:   entry.Level,
		Message: bufCopy,
	}

	if entry.Level <= h.syslogLevel {
		// syslog gets its own log string since our default log string duplicates a lot of
		// syslog metadata.  Only calculate that string if it's needed.
		ql.SyslogMessage = FormatForSyslog(entry)
	}

	var waitGroup *sync.WaitGroup
	if entry.Level <= log.FatalLevel || entry.Data[FieldForceFlush] == true {
		// If the process is about to be killed (or we're asked to do so), flush the log.
		waitGroup = &sync.WaitGroup{}
		ql.WaitGroup = waitGroup
	}

	for _, dest := range h.destinations {
		if ql.Level > dest.Level {
			continue
		}
		if waitGroup != nil {
			// Thread safety: we must call add before we send the wait group over the
			// channel (or the background thread could be scheduled immediately and
			// call Done() before we call Add()).  Since we don't know if the send
			// will succeed that leads to the need to call Done() on the 'default:'
			// branch below to correctly pair Add()/Done() calls.
			waitGroup.Add(1)
		}

		if ok := dest.Send(ql); !ok {
			// Background thread isn't keeping up.  Drop the log and count how many
			// we've dropped.
			if waitGroup != nil {
				waitGroup.Done()
			}
			// Increment the number of dropped logs
			dest.counter.Inc()
		}
	}
	if waitGroup != nil {
		waitGroup.Wait()
	}
	return
}

func (h *BackgroundHook) Start() {
	for _, d := range h.destinations {
		go d.LoopWritingLogs()
	}
}

// SafeParseLogLevel parses a string version of a logrus log level, defaulting to logrus.PanicLevel on failure.
func SafeParseLogLevel(logLevel string) log.Level {
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
