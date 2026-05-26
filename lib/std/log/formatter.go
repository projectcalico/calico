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
	"bytes"
	"fmt"
	"os"
	"path"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// fileNameUnknown is the string used in logs when the filename/line number
// cannot be determined.
const fileNameUnknown = "<nil>"

// FieldForceFlush is a log field that, when set to true, signals to the
// background destination hook to wait for the log to flush before returning.
// Useful immediately before a process exit. Use as:
//
//	log.WithField(log.FieldForceFlush, true).Info("about to exit")
const FieldForceFlush = "__flush__"

// fieldForceFlush is the internal alias for FieldForceFlush kept for use
// inside the formatter without circular references.
const fieldForceFlush = FieldForceFlush

// fieldComponent carries the per-logger component name set by New(component).
// The formatter promotes it to the log line's file-path prefix and strips it
// from the key/value output. Internal-only.
const fieldComponent = "__component__"

// timeFormat is the timestamp format used in log lines.
const timeFormat = "2006-01-02 15:04:05.000"

const timeFormatLen = len(timeFormat)

// formatter is the Calico log formatter. It produces lines like:
//
//	2017-01-05 09:17:48.238 [INFO][85386] felix/endpoint_mgr.go 434: msg key="value"
//
// Format is preserved byte-for-byte from libcalico-go/lib/logutils so operator
// grep patterns continue to work.
type formatter struct {
	component string

	initOnce                sync.Once
	preComputedInfixByLevel []string
}

var maxLogrusLevel = logrus.Level(len(logrus.AllLevels))

func newFormatter(component string) *formatter {
	f := &formatter{component: component}
	f.init()
	return f
}

func (f *formatter) init() {
	f.initOnce.Do(func() {
		f.preComputedInfixByLevel = make([]string, len(logrus.AllLevels))
		for _, level := range logrus.AllLevels {
			var buf bytes.Buffer
			f.computeInfix(&buf, level)
			f.preComputedInfixByLevel[level] = buf.String()
		}
	})
}

func (f *formatter) Format(entry *logrus.Entry) ([]byte, error) {
	f.init()

	b := entry.Buffer
	if b == nil {
		b = &bytes.Buffer{}
	}

	fileName, lineNo := f.callerInfo(entry)
	component := f.componentFor(entry)

	b.Grow(timeFormatLen + 32 + len(component) + len(fileName) + len(entry.Message) + len(entry.Data)*32)
	appendTime(b, entry.Time)
	f.writeInfix(b, entry.Level)
	if component != "" {
		b.WriteString(component)
		b.WriteByte('/')
	}
	b.WriteString(fileName)
	b.WriteByte(' ')
	if lineNo == 0 {
		b.WriteString(fileNameUnknown)
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

func (f *formatter) writeInfix(b *bytes.Buffer, level logrus.Level) {
	if level >= maxLogrusLevel {
		f.computeInfix(b, level)
		return
	}
	_, _ = b.WriteString(f.preComputedInfixByLevel[level])
}

func (f *formatter) computeInfix(b *bytes.Buffer, level logrus.Level) {
	_, _ = fmt.Fprintf(b, " [%s][%d] ", strings.ToUpper(level.String()), os.Getpid())
}

// componentFor returns the component label to use for this entry. A
// per-logger component attached via New() wins; otherwise the formatter's
// global component (set via SetComponent/Configure) is used.
func (f *formatter) componentFor(entry *logrus.Entry) string {
	if c, ok := entry.Data[fieldComponent].(string); ok && c != "" {
		return c
	}
	return f.component
}

// callerInfo returns the file basename and line number of the user code
// that invoked the log call. If entry.Caller was populated by the caller
// (e.g. a unit test setting a specific frame), it wins; otherwise we walk
// the stack ourselves so we can skip both logrus frames and lib/std/log
// wrapper frames. Production code never sets entry.Caller — we force
// logrus.SetReportCaller(false) on the first Format call — so the stack
// walk is what runs in practice.
func (f *formatter) callerInfo(entry *logrus.Entry) (string, int) {
	if entry.Caller != nil {
		return path.Base(entry.Caller.File), entry.Caller.Line
	}
	frame := findUserCaller()
	if frame == nil {
		return fileNameUnknown, 0
	}
	return path.Base(frame.File), frame.Line
}

// appendTime appends the time to the buffer in our format "2006-01-02 15:04:05.000".
// It uses RFC3339Nano's optimised formatter and rewrites the result in place.
func appendTime(b *bytes.Buffer, t time.Time) {
	b.Grow(timeFormatLen)
	buf := b.AvailableBuffer()
	buf = t.AppendFormat(buf, time.RFC3339Nano)
	buf = buf[:timeFormatLen]
	const tPos = len("2006-01-02T") - 1
	buf[tPos] = ' '
	const dotPos = len("2006-01-02T15:04:05.") - 1

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

var preComputedInfixByLevelSyslog = func() []string {
	out := make([]string, len(logrus.AllLevels))
	for _, level := range logrus.AllLevels {
		out[level] = strings.ToUpper(level.String()) + " "
	}
	return out
}()

// formatForSyslog formats logs for syslog, omitting timestamp/PID (which syslog
// adds itself) and keeping the level.
func formatForSyslog(entry *logrus.Entry, component string) string {
	b := entry.Buffer
	if b == nil {
		b = &bytes.Buffer{}
	}

	var fileName string
	var lineNo int
	if entry.Caller != nil {
		fileName, lineNo = path.Base(entry.Caller.File), entry.Caller.Line
	} else if frame := findUserCaller(); frame != nil {
		fileName, lineNo = path.Base(frame.File), frame.Line
	} else {
		fileName = fileNameUnknown
	}

	b.Grow(32 + len(fileName) + len(entry.Message) + len(entry.Data)*32)
	if entry.Level < maxLogrusLevel {
		b.WriteString(preComputedInfixByLevelSyslog[entry.Level])
	} else {
		b.WriteString(strings.ToUpper(entry.Level.String()))
		b.WriteByte(' ')
	}
	if component != "" {
		b.WriteString(component)
		b.WriteByte('/')
	}
	b.WriteString(fileName)
	b.WriteByte(' ')
	if lineNo == 0 {
		b.WriteString(fileNameUnknown)
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

// appendKVsAndNewLine writes the entry's key/value pairs to the end of the buffer,
// in sorted order, followed by a newline.
func appendKVsAndNewLine(b *bytes.Buffer, data logrus.Fields) {
	if len(data) == 0 {
		b.WriteByte('\n')
		return
	}

	var keys []string
	const arrSize = 16
	if len(data) < arrSize {
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
		if key == fieldForceFlush || key == fieldComponent {
			continue
		}
		value := data[key]
		b.WriteByte(' ')
		b.WriteString(key)
		b.WriteByte('=')

		switch v := value.(type) {
		case string:
			buf := b.AvailableBuffer()
			buf = strconv.AppendQuote(buf, v)
			b.Write(buf)
		case *string:
			if v == nil {
				b.WriteString("<nil>")
			} else {
				b.WriteByte('*')
				buf := b.AvailableBuffer()
				buf = strconv.AppendQuote(buf, *v)
				b.Write(buf)
			}
		case error:
			b.WriteString(v.Error())
		case fmt.Stringer:
			b.WriteString(v.String())
		default:
			_, _ = fmt.Fprintf(b, "%#v", value)
		}
	}
	b.WriteByte('\n')
}

// Caller detection. We walk the stack ourselves rather than rely on logrus's
// SetReportCaller because logrus would report our wrapper functions as the
// caller. We skip frames in logrus and in this package.

const (
	logrusPackage      = "github.com/sirupsen/logrus"
	thisPackagePrefix  = "github.com/projectcalico/calico/lib/std/log"
	maxCallerDepth     = 25
	minimumCallerDepth = 1
)

func findUserCaller() *runtime.Frame {
	pcs := make([]uintptr, maxCallerDepth)
	n := runtime.Callers(minimumCallerDepth, pcs)
	if n == 0 {
		return nil
	}
	frames := runtime.CallersFrames(pcs[:n])
	for {
		f, more := frames.Next()
		pkg := getPackageName(f.Function)
		if !isInternalPackage(pkg) {
			frame := f
			return &frame
		}
		if !more {
			break
		}
	}
	return nil
}

func isInternalPackage(pkg string) bool {
	return pkg == logrusPackage ||
		strings.HasPrefix(pkg, logrusPackage+"/") ||
		pkg == thisPackagePrefix ||
		strings.HasPrefix(pkg, thisPackagePrefix+"/")
}

// getPackageName extracts the package name from a fully qualified function name.
// e.g. "github.com/x/y/pkg.Func" → "github.com/x/y/pkg".
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
