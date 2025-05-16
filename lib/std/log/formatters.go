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

package log

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

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
	pc, _, _, ok := runtime.Caller(0)
	if !ok {
		return
	}

	fn := runtime.FuncForPC(pc).Name()
	logPkgName = getPackageName(fn)
}

type Formatter interface {
	Format(Entry) ([]byte, error)
}

// defaultFormatter is our custom log formatter designed to balance ease of machine processing
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
type defaultFormatter struct {
	// If specified, prepends the component to the file name. This is useful for when
	// multiple components are logging to the same file (e.g., calico/node) for distinguishing
	// which component sourced the logrus.
	component string

	initOnce                sync.Once
	preComputedInfixByLevel []string
}

func NewDefaultFormatter() Formatter {
	return NewDefaultFormatterWithName("")
}

func NewDefaultFormatterWithName(name string) Formatter {
	f := &defaultFormatter{component: name}
	f.preComputedInfixByLevel = make([]string, len(AllLevels))
	for _, level := range AllLevels {
		var buf bytes.Buffer
		f.computeInfix(&buf, level)
		f.preComputedInfixByLevel[level] = buf.String()
	}
	return f
}

func (f *defaultFormatter) Format(entry Entry) ([]byte, error) {
	b := entry.buffer()
	if b == nil {
		b = &bytes.Buffer{}
	}

	fileName, lineNo := getFileInfo(entry)

	b.Grow(timeFormatLen + 32 + len(fileName) + len(entry.message()) + len(entry.Fields())*32)
	AppendTime(b, entry.GetTime())
	f.writeInfix(b, entry.GetLevel())
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
	b.WriteString(entry.message())
	appendKVsAndNewLine(b, entry.Fields())

	return b.Bytes(), nil
}

func (f *defaultFormatter) writeInfix(b *bytes.Buffer, level Level) {
	if level >= maxLevel {
		// Slow path for unknown log levels.
		f.computeInfix(b, level)
	}
	_, _ = b.WriteString(f.preComputedInfixByLevel[level])
}

func (f *defaultFormatter) computeInfix(b *bytes.Buffer, level Level) {
	_, _ = fmt.Fprintf(b, " [%s][%d] ", strings.ToUpper(level.String()), os.Getpid())
	if f.component != "" {
		_, _ = fmt.Fprintf(b, "%s/", f.component)
	}
}

var preComputedInfixByLevelSyslog = make([]string, len(AllLevels))

func init() {
	for _, level := range AllLevels {
		preComputedInfixByLevelSyslog[level] = strings.ToUpper(level.String()) + " "
	}
}

// FormatForSyslog formats logs in a way tailored for syslogrus.  It avoids logging information that is
// already included in the syslog metadata such as timestamp and PID.  The log level _is_ included
// because syslog doesn't seem to output it by default and it's very useful.
//
//	INFO endpoint_mgr.go 434: Skipping configuration of interface because it is oper down.
//	ifaceName="cali1234"
func FormatForSyslog(entry Entry) string {
	b := entry.buffer()
	if b == nil {
		b = &bytes.Buffer{}
	}

	fileName, lineNo := getFileInfo(entry)

	b.Grow(timeFormatLen + 32 + len(fileName) + len(entry.message()) + len(entry.Fields())*32)
	if entry.GetLevel() < maxLevel {
		b.WriteString(preComputedInfixByLevelSyslog[entry.GetLevel()])
	} else {
		b.WriteString(strings.ToUpper(entry.GetLevel().String()))
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
	b.WriteString(entry.message())
	appendKVsAndNewLine(b, entry.Fields())

	return b.String()
}

var forTest bool

func MarkForTesting() {
	forTest = true
}

func getFileInfo(entry Entry) (string, int) {
	caller := entry.caller()
	if caller == nil {
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
		if pcs[i] == caller.PC+1 {
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
			break
		}

		// Unfortunately, to properly test this, we need to signal to include test files from this package.
		if forTest && strings.HasSuffix(frame.File, "_test.go") {
			targetFrame = frame
			break
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
func appendKVsAndNewLine(b *bytes.Buffer, data Fields) {
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
	Level         Level
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
	level Level,
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
	level Level,
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
	Level Level
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
	case PanicLevel:
		return writer.Crit(ql.SyslogMessage)
	case FatalLevel:
		return writer.Crit(ql.SyslogMessage)
	case ErrorLevel:
		return writer.Err(ql.SyslogMessage)
	case WarnLevel:
		return writer.Warning(ql.SyslogMessage)
	case InfoLevel:
		return writer.Info(ql.SyslogMessage)
	case DebugLevel:
		return writer.Debug(ql.SyslogMessage)
	default:
		return nil
	}
}

type TextFormatterConfig struct {
	// Set to true to bypass checking for a TTY before outputting colors.
	ForceColors bool

	// Force disabling colors.
	DisableColors bool

	// Force quoting of all values
	ForceQuote bool

	// DisableQuote disables quoting for all values.
	// DisableQuote will have a lower priority than ForceQuote.
	// If both of them are set to true, quote will be forced on all values.
	DisableQuote bool

	// Override coloring based on CLICOLOR and CLICOLOR_FORCE. - https://bixense.com/clicolors/
	EnvironmentOverrideColors bool

	// Disable timestamp logging. useful when output is redirected to logging
	// system that already adds timestamps.
	DisableTimestamp bool

	// Enable logging the full timestamp when a TTY is attached instead of just
	// the time passed since beginning of execution.
	FullTimestamp bool

	// TimestampFormat to use for display when a full timestamp is printed.
	// The format to use is the same than for time.Format or time.Parse from the standard
	// library.
	// The standard Library already provides a set of predefined format.
	TimestampFormat string

	// The fields are sorted by default for a consistent output. For applications
	// that log extremely frequently and don't use the JSON formatter this may not
	// be desired.
	DisableSorting bool

	// The keys sorting function, when uninitialized it uses sort.Strings.
	SortingFunc func([]string)

	// Disables the truncation of the level text to 4 characters.
	DisableLevelTruncation bool

	// PadLevelText Adds padding the level text so that all the levels output at the same length
	// PadLevelText is a superset of the DisableLevelTruncation option
	PadLevelText bool

	// QuoteEmptyFields will wrap empty fields in quotes if true
	QuoteEmptyFields bool

	// CallerPrettyfier can be set by the user to modify the content
	// of the function and file keys in the data when ReportCaller is
	// activated. If any of the returned value is the empty string the
	// corresponding key will be removed from fields.
	CallerPrettyfier func(*runtime.Frame) (function string, file string)
}

func NewTextFormatter(cfg TextFormatterConfig) Formatter {
	return &logrusWrapper{&logrus.TextFormatter{
		ForceColors:            cfg.ForceColors,
		DisableColors:          cfg.DisableColors,
		ForceQuote:             cfg.ForceQuote,
		DisableTimestamp:       cfg.DisableTimestamp,
		DisableLevelTruncation: cfg.DisableLevelTruncation,
		PadLevelText:           cfg.PadLevelText,
		QuoteEmptyFields:       cfg.QuoteEmptyFields,
		FullTimestamp:          cfg.FullTimestamp,
		TimestampFormat:        cfg.TimestampFormat,
		DisableSorting:         cfg.DisableSorting,
		SortingFunc:            cfg.SortingFunc,
		CallerPrettyfier:       cfg.CallerPrettyfier,
	}}
}
