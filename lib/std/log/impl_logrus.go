// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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
	"os"

	"github.com/sirupsen/logrus"
)

// logrusLogger is the only Logger implementation. It wraps a *logrus.Entry.
// New returns one of these; nothing in the public API exposes *logrus.Entry
// directly.
type logrusLogger struct {
	entry *logrus.Entry
}

func newLogrusLogger(entry *logrus.Entry) *logrusLogger {
	return &logrusLogger{entry: entry}
}

// New returns a Logger labelled with the given component name. The component
// appears in every log line emitted via the returned Logger as a prefix on
// the file name (e.g. "felix/calc_graph.go"). The per-logger component
// overrides any component set via SetComponent or Configure.
//
// An empty component is treated as "no override": lines fall back to whatever
// the global formatter carries.
func New(component string) Logger {
	entry := logrus.NewEntry(logrus.StandardLogger())
	if component != "" {
		entry = entry.WithField(fieldComponent, component)
	}
	return newLogrusLogger(entry)
}

// Emit methods. Each delegates to the underlying logrus entry.

func (l *logrusLogger) Trace(args ...any)                   { l.entry.Trace(args...) }
func (l *logrusLogger) Tracef(format string, args ...any)   { l.entry.Tracef(format, args...) }
func (l *logrusLogger) Debug(args ...any)                   { l.entry.Debug(args...) }
func (l *logrusLogger) Debugf(format string, args ...any)   { l.entry.Debugf(format, args...) }
func (l *logrusLogger) Info(args ...any)                    { l.entry.Info(args...) }
func (l *logrusLogger) Infof(format string, args ...any)    { l.entry.Infof(format, args...) }
func (l *logrusLogger) Warn(args ...any)                    { l.entry.Warn(args...) }
func (l *logrusLogger) Warnf(format string, args ...any)    { l.entry.Warnf(format, args...) }
func (l *logrusLogger) Warning(args ...any)                 { l.entry.Warning(args...) }
func (l *logrusLogger) Warningf(format string, args ...any) { l.entry.Warningf(format, args...) }
func (l *logrusLogger) Error(args ...any)                   { l.entry.Error(args...) }
func (l *logrusLogger) Errorf(format string, args ...any)   { l.entry.Errorf(format, args...) }

// Fatal/Panic methods split logging from termination so static analyzers
// (notably staticcheck SA5011) can see the terminating call in the wrapper
// body and treat callers' nil-checks as guaranteed terminators. logrus's
// Entry.Log/Logf/Logln explicitly do not exit/panic at Fatal/Panic level,
// leaving us to call os.Exit / panic ourselves.

func (l *logrusLogger) Fatal(args ...any) {
	l.entry.Log(logrus.FatalLevel, args...)
	os.Exit(1)
}

func (l *logrusLogger) Fatalf(format string, args ...any) {
	l.entry.Logf(logrus.FatalLevel, format, args...)
	os.Exit(1)
}

func (l *logrusLogger) Panic(args ...any) {
	l.entry.Log(logrus.PanicLevel, args...)
	panic(fmt.Sprint(args...))
}

func (l *logrusLogger) Panicf(format string, args ...any) {
	l.entry.Logf(logrus.PanicLevel, format, args...)
	panic(fmt.Sprintf(format, args...))
}

// Print/Printf/Println emit at Info level (logrus.Entry.Print* also do this).
func (l *logrusLogger) Print(args ...any)                 { l.entry.Print(args...) }
func (l *logrusLogger) Printf(format string, args ...any) { l.entry.Printf(format, args...) }
func (l *logrusLogger) Println(args ...any)               { l.entry.Println(args...) }

func (l *logrusLogger) Debugln(args ...any)   { l.entry.Debugln(args...) }
func (l *logrusLogger) Infoln(args ...any)    { l.entry.Infoln(args...) }
func (l *logrusLogger) Warnln(args ...any)    { l.entry.Warnln(args...) }
func (l *logrusLogger) Warningln(args ...any) { l.entry.Warningln(args...) }
func (l *logrusLogger) Errorln(args ...any)   { l.entry.Errorln(args...) }

func (l *logrusLogger) Fatalln(args ...any) {
	l.entry.Logln(logrus.FatalLevel, args...)
	os.Exit(1)
}

func (l *logrusLogger) Panicln(args ...any) {
	l.entry.Logln(logrus.PanicLevel, args...)
	panic(fmt.Sprintln(args...))
}

func (l *logrusLogger) WithField(key string, value any) Logger {
	return &logrusLogger{entry: l.entry.WithField(key, value)}
}

func (l *logrusLogger) WithFields(fields Fields) Logger {
	return &logrusLogger{entry: l.entry.WithFields(logrus.Fields(fields))}
}

func (l *logrusLogger) WithError(err error) Logger {
	return &logrusLogger{entry: l.entry.WithError(err)}
}

func (l *logrusLogger) Level() Level {
	return Level(l.entry.Logger.GetLevel())
}

func (l *logrusLogger) IsLevelEnabled(level Level) bool {
	return l.entry.Logger.IsLevelEnabled(logrus.Level(level))
}
