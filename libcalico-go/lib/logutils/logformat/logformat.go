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

// Package logformat contains Calico's custom logrus formatter and the small
// set of helpers needed to use it.  It deliberately depends only on the
// standard library and logrus so that lightweight command-line tools can
// import it to get consistent log formatting without pulling in the heavier
// dependency tree (Prometheus, etc.) of the parent logutils package.
package logformat

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// FieldForceFlush is a field name used to signal to the BackgroundHook that it should flush the log after this
	// message.  It can be used as follows: logrus.WithField(FieldForceFlush, true).Info("...")
	FieldForceFlush = "__flush__"

	// FileNameUnknown is the string used in logs if the filename/line number
	// cannot be determined.
	FileNameUnknown = "<nil>"
)

func init() {
	// We need logrus to record the caller on each log entry for us.
	log.SetReportCaller(true)
}

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

func ConfigureFormatter(componentName string) {
	formatter := &Formatter{Component: componentName}
	formatter.init()
	log.SetFormatter(formatter)
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
	// which component sourced the log.
	Component string

	initOnce                sync.Once
	preComputedInfixByLevel []string
}

var maxLevel = log.Level(len(log.AllLevels))

func (f *Formatter) init() {
	f.initOnce.Do(func() {
		f.preComputedInfixByLevel = make([]string, len(log.AllLevels))
		for _, level := range log.AllLevels {
			var buf bytes.Buffer
			f.computeInfix(&buf, level)
			f.preComputedInfixByLevel[level] = buf.String()
		}
	})
}

const TimeFormat = "2006-01-02 15:04:05.000"
const timeFormatLen = len(TimeFormat)

func (f *Formatter) Format(entry *log.Entry) ([]byte, error) {
	f.init()

	b := entry.Buffer
	if b == nil {
		b = &bytes.Buffer{}
	}

	fileName, lineNo := GetFileInfo(entry)

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

func (f *Formatter) writeInfix(b *bytes.Buffer, level log.Level) {
	if level >= maxLevel {
		// Slow path for unknown log levels.
		f.computeInfix(b, level)
	}
	_, _ = b.WriteString(f.preComputedInfixByLevel[level])
}

func (f *Formatter) computeInfix(b *bytes.Buffer, level log.Level) {
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

var preComputedInfixByLevelSyslog = make([]string, len(log.AllLevels))

func init() {
	for _, level := range log.AllLevels {
		preComputedInfixByLevelSyslog[level] = strings.ToUpper(level.String()) + " "
	}
}

// FormatForSyslog formats logs in a way tailored for syslog.  It avoids logging information that is
// already included in the syslog metadata such as timestamp and PID.  The log level _is_ included
// because syslog doesn't seem to output it by default and it's very useful.
//
//	INFO endpoint_mgr.go 434: Skipping configuration of interface because it is oper down.
//	ifaceName="cali1234"
func FormatForSyslog(entry *log.Entry) string {
	b := entry.Buffer
	if b == nil {
		b = &bytes.Buffer{}
	}

	fileName, lineNo := GetFileInfo(entry)

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

// GetFileInfo returns the base file name and line number recorded on the log
// entry, or (FileNameUnknown, 0) if the caller could not be determined.
func GetFileInfo(entry *log.Entry) (string, int) {
	if entry.Caller == nil {
		return FileNameUnknown, 0
	}
	return path.Base(entry.Caller.File), entry.Caller.Line
}

// appendKVsAndNewLine writes the entry's KV pairs to the end of the buffer,
// followed by a newline.  Entries are written in sorted order.
func appendKVsAndNewLine(b *bytes.Buffer, data log.Fields) {
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
		case *string:
			if value == nil {
				b.WriteString("<nil>")
			} else {
				b.WriteByte('*')
				buf := b.AvailableBuffer()
				buf = strconv.AppendQuote(buf, *value)
				b.Write(buf)
			}
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
