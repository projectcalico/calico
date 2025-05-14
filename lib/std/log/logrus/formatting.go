// Copyright (c) 2016-2024 Tigera, Inc. All rights reserved.
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

package logrus

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	// FieldForceFlush is a field name used to signal to the BackgroundHook that it should flush the log after this
	// message.  It can be used as follows: logrus.WithField(FieldForceFlush, true).Info("...")
	FieldForceFlush = "__flush__"

	// FileNameUnknown is the string used in logs if the filename/line number
	// cannot be determined.
	FileNameUnknown = "<nil>"
)

var (
	// This is the name of this package as calculated by the runtime package.
	logPkgName string
)

func init() {
	// We need logrus to record the caller on each log entry for us.
	logrus.SetReportCaller(true)

	pc, _, _, ok := runtime.Caller(0)
	if !ok {
		return
	}

	fn := runtime.FuncForPC(pc).Name()
	logPkgName = strings.TrimSuffix(getPackageName(fn), "/logrus")
}

type MetricsCounter interface {
	// Inc increments the counter by 1. Use Add to increment it by arbitrary
	// non-negative values.
	Inc()
	// Add adds the given value to the counter. It panics if the value is <
	// 0.
	Add(float64)
}

// FilterLevels returns all the logrus.Level values <= maxLevel.
func FilterLevels(maxLevel logrus.Level) []logrus.Level {
	levels := []logrus.Level{}
	for _, l := range logrus.AllLevels {
		if l <= maxLevel {
			levels = append(levels, l)
		}
	}
	return levels
}

func ConfigureFormatter(componentName string) {
	formatter := &Formatter{Component: componentName}
	formatter.init()
	logrus.SetFormatter(formatter)
}

// Formatter is our custom log formatter designed to balance ease of machine processing
// with human readability.  Logs include:
//   - A sortable millisecond timestamp, for scanning and correlating logs
//   - The log level, near the beginning of the line, to aid in visual scanning
//   - The PID of the process to make it easier to spot log discontinuities (If
//     you are looking at two disjoint chunks of log, were they written by the
//     same process?  Was there a restart in-between?)
//   - The file name and line number, as essential context
//   - The message!
//   - Log fields appended in sorted order
//
// Example:
//
//	2017-01-05 09:17:48.238 [INFO][85386] endpoint_mgr.go 434: Skipping configuration of
//	interface because it is oper down. ifaceName="cali1234"
type Formatter struct {
	// If specified, prepends the component to the file name. This is useful for when
	// multiple components are logging to the same file (e.g., calico/node) for distinguishing
	// which component sourced the logrus.
	Component string

	initOnce                sync.Once
	preComputedInfixByLevel []string
}

var maxLevel = logrus.Level(len(logrus.AllLevels))

func (f *Formatter) init() {
	f.initOnce.Do(func() {
		f.preComputedInfixByLevel = make([]string, len(logrus.AllLevels))
		for _, level := range logrus.AllLevels {
			var buf bytes.Buffer
			f.computeInfix(&buf, level)
			f.preComputedInfixByLevel[level] = buf.String()
		}
	})
}

const TimeFormat = "2006-01-02 15:04:05.000"
const timeFormatLen = len(TimeFormat)

func (f *Formatter) Format(entry *logrus.Entry) ([]byte, error) {
	f.init()

	b := entry.Buffer
	if b == nil {
		b = &bytes.Buffer{}
	}

	fileName, lineNo := getFileInfo(entry)

	b.Grow(timeFormatLen + 32 + len(fileName) + len(entry.Message) + len(entry.Data)*32)
	AppendTime(b, entry.Time)
	f.writeInfix(b, entry.Level)
	b.WriteString(fileName)
	b.WriteByte(' ')
	if lineNo == 0 {
		b.WriteString(FileNameUnknown)
	} else {
		buf := b.AvailableBuffer()
		buf = strconv.AppendInt(buf, int64(lineNo), 10)
		_, _ = b.Write(buf)
	}
	b.WriteString(": ")
	b.WriteString(entry.Message)
	appendKVsAndNewLine(b, entry.Data)

	return b.Bytes(), nil
}

func (f *Formatter) writeInfix(b *bytes.Buffer, level logrus.Level) {
	if level >= maxLevel {
		// Slow path for unknown log levels.
		f.computeInfix(b, level)
	}
	_, _ = b.WriteString(f.preComputedInfixByLevel[level])
}

func (f *Formatter) computeInfix(b *bytes.Buffer, level logrus.Level) {
	_, _ = fmt.Fprintf(b, " [%s][%d] ", strings.ToUpper(level.String()), os.Getpid())
	if f.Component != "" {
		_, _ = fmt.Fprintf(b, "%s/", f.Component)
	}
}

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

var preComputedInfixByLevelSyslog = make([]string, len(logrus.AllLevels))

func init() {
	for _, level := range logrus.AllLevels {
		preComputedInfixByLevelSyslog[level] = strings.ToUpper(level.String()) + " "
	}
}

// FormatForSyslog formats logs in a way tailored for syslogrus.  It avoids logging information that is
// already included in the syslog metadata such as timestamp and PID.  The log level _is_ included
// because syslog doesn't seem to output it by default and it's very useful.
//
//	INFO endpoint_mgr.go 434: Skipping configuration of interface because it is oper down.
//	ifaceName="cali1234"
func FormatForSyslog(entry *logrus.Entry) string {
	b := entry.Buffer
	if b == nil {
		b = &bytes.Buffer{}
	}

	fileName, lineNo := getFileInfo(entry)

	b.Grow(timeFormatLen + 32 + len(fileName) + len(entry.Message) + len(entry.Data)*32)
	if entry.Level < maxLevel {
		b.WriteString(preComputedInfixByLevelSyslog[entry.Level])
	} else {
		b.WriteString(strings.ToUpper(entry.Level.String()))
		b.WriteByte(' ')
	}
	b.WriteString(fileName)
	b.WriteByte(' ')
	if lineNo == 0 {
		b.WriteString(FileNameUnknown)
	} else {
		buf := b.AvailableBuffer()
		buf = strconv.AppendInt(buf, int64(lineNo), 10)
		_, _ = b.Write(buf)
	}
	b.WriteString(": ")
	b.WriteString(entry.Message)
	appendKVsAndNewLine(b, entry.Data)

	return b.String()
}

func getFileInfo(entry *logrus.Entry) (string, int) {
	if entry.Caller == nil {
		return FileNameUnknown, 0
	}

	pcs := make([]uintptr, 25)
	n := runtime.Callers(0, pcs)
	startIdx := -1
	// Find the index that we want to start returning frames for by first finding the frame from Callers that matches
	// the frame that logrus stored. This reduces the overhead of grabbing frames we don't need.
	for i := 0; i < n; i++ {
		// Compare the program counters from the caller stack retrieve to the one logrus stored. We need to offset the
		// counter in the entry frame by +1 to match the counters returned by callers. This matches as outlined by the
		// comment in frames.Next:
		// 	// We store the pc of the start of the instruction following
		// 	// the instruction in question (the call or the inline mark).
		// 	// This is done for historical reasons, and to make FuncForPC
		// 	// work correctly for entries in the result of runtime.Callers.
		// 	// Decrement to get back to the instruction we care about.
		if pcs[i] == entry.Caller.PC+1 {
			startIdx = i
			break
		}
	}

	var targetFrame runtime.Frame
	frames := runtime.CallersFrames(pcs[startIdx+1 : n])
	for frame, more := frames.Next(); more; frame, more = frames.Next() {
		pkg := getPackageName(frame.Function)
		// The first frame that doesn't match the log package is the caller that we want to log.
		if !strings.HasPrefix(pkg, logPkgName) {
			targetFrame = frame
		}
	}

	return path.Base(targetFrame.File), targetFrame.Line
}

// getPackageName reduces a fully qualified function name to the package name
// There really ought to be a better way...
func getPackageName(f string) string {
	for {
		lastPeriod := strings.LastIndex(f, ".")
		lastSlash := strings.LastIndex(f, "/")
		if lastPeriod > lastSlash {
			f = f[:lastPeriod]
		} else {
			break
		}
	}

	return f
}

// appendKeysAndNewLine writes the entry's KV pairs to the end of the buffer,
// followed by a newline.  Entries are written in sorted order.
func appendKVsAndNewLine(b *bytes.Buffer, data logrus.Fields) {
	if len(data) == 0 {
		b.WriteByte('\n')
		return
	}

	// Sort the keys for consistent output.
	var keys []string
	const arrSize = 16
	if len(data) < arrSize {
		// Optimisation: avoid an allocation if the number of keys is small.
		// make(...) always spills to the heap if the slice size is not known at
		// compile time.
		var dataArr [arrSize]string
		keys = dataArr[:0]
	} else {
		keys = make([]string, 0, len(data))
	}
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		if key == FieldForceFlush {
			continue
		}
		var value = data[key]
		b.WriteByte(' ')
		b.WriteString(key)
		b.WriteByte('=')

		switch value := value.(type) {
		case string:
			buf := b.AvailableBuffer()
			buf = strconv.AppendQuote(buf, value)
			b.Write(buf)
		case error:
			b.WriteString(value.Error())
		case fmt.Stringer:
			// Trust the value's String() method.
			b.WriteString(value.String())
		default:
			// No string method, use %#v to get a more thorough dump.
			_, _ = fmt.Fprintf(b, "%#v", value)
		}
	}
	b.WriteByte('\n')
}

// NullWriter is a dummy writer that always succeeds and does nothing.
type NullWriter struct{}

func (w *NullWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

type QueuedLog struct {
	Level         logrus.Level
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
	level logrus.Level,
	writer io.Writer,
	c chan QueuedLog,
	disableLogDropping bool,
	counter MetricsCounter,
) *Destination {
	return &Destination{
		Level:   level,
		Channel: c,
		writeLog: func(ql QueuedLog) error {
			if ql.NumSkippedLogs > 0 {
				_, _ = fmt.Fprintf(writer, "... dropped %d logs ...\n",
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
	level logrus.Level,
	writer syslogWriter,
	c chan QueuedLog,
	disableLogDropping bool,
	counter MetricsCounter,
) *Destination {
	return &Destination{
		Level:   level,
		Channel: c,
		writeLog: func(ql QueuedLog) error {
			if ql.NumSkippedLogs > 0 {
				_ = writer.Warning(fmt.Sprintf("... dropped %d logs ...\n",
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
	Level logrus.Level
	// Channel is the channel used to queue logs to the background worker thread.  Public for
	// test purposes.
	Channel chan QueuedLog
	// WriteLog is the function to actually make a logrus.  The constructors above initialise this
	// with a function that logs to a stream or to syslog, for example.
	writeLog func(ql QueuedLog) error

	// DisableLogDropping forces all logs to be queued even if the destination blocks.
	disableLogDropping bool

	// Lock protects the numDroppedLogs count.
	lock           sync.Mutex
	numDroppedLogs uint

	// Counter is the metrics counter for logged errors that this destination will increment
	counter MetricsCounter
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
	case logrus.PanicLevel:
		return writer.Crit(ql.SyslogMessage)
	case logrus.FatalLevel:
		return writer.Crit(ql.SyslogMessage)
	case logrus.ErrorLevel:
		return writer.Err(ql.SyslogMessage)
	case logrus.WarnLevel:
		return writer.Warning(ql.SyslogMessage)
	case logrus.InfoLevel:
		return writer.Info(ql.SyslogMessage)
	case logrus.DebugLevel:
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
	levels          []logrus.Level
	syslogLevel     logrus.Level
	debugFileNameRE *regexp.Regexp

	destinations []*Destination

	// Counter
	counter MetricsCounter
}

type BackgroundHookOpt func(hook *BackgroundHook)

func WithDebugFileRegexp(re *regexp.Regexp) BackgroundHookOpt {
	return func(hook *BackgroundHook) {
		hook.debugFileNameRE = re
	}
}

var _ = WithDebugFileRegexp

func NewBackgroundHook(
	levels []logrus.Level,
	syslogLevel logrus.Level,
	destinations []*Destination,
	counter MetricsCounter,
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

func (h *BackgroundHook) Levels() []logrus.Level {
	return h.levels
}

func (h *BackgroundHook) Fire(entry *logrus.Entry) (err error) {
	if entry.Buffer != nil {
		defer entry.Buffer.Truncate(0)
	}

	if entry.Level >= logrus.DebugLevel && h.debugFileNameRE != nil {
		// This is a debug log, check if debug logging is enabled for this file.
		fileName, _ := getFileInfo(entry)
		if fileName == FileNameUnknown || !h.debugFileNameRE.MatchString(fileName) {
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
	if entry.Level <= logrus.FatalLevel || entry.Data[FieldForceFlush] == true {
		// If the process is about to be killed (or we're asked to do so), flush the logrus.
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
func SafeParseLogLevel(logLevel string) logrus.Level {
	defaultedLevel := logrus.PanicLevel
	if logLevel != "" {
		parsedLevel, err := logrus.ParseLevel(logLevel)
		if err == nil {
			defaultedLevel = parsedLevel
		} else {
			logrus.WithField("raw level", logLevel).Warn(
				"Invalid log level, defaulting to panic")
		}
	}
	return defaultedLevel
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

// RedirectLogrusToTestingT redirects logrus output to the given testing.T.  It
// returns a func() that can be called to restore the original log output.
func RedirectLogrusToTestingT(t *testing.T) (cancel func()) {
	oldOut := logrus.StandardLogger().Out
	cancel = func() {
		logrus.SetOutput(oldOut)
	}
	logrus.SetOutput(TestingTWriter{T: t})
	return
}

var confForTestingOnce sync.Once

// ConfigureLoggingForTestingT configures logrus to write to the logger of the
// given testing.T.  It should be called at the start of each "go test" that
// wants to capture log output.  It registers a cleanup with the testing.T to
// remove the log redirection at the end of the test.
func ConfigureLoggingForTestingT(t *testing.T) {
	confForTestingOnce.Do(func() {
		logrus.SetFormatter(&Formatter{Component: "test"})
	})
	t.Cleanup(RedirectLogrusToTestingT(t))
}
