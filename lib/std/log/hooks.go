// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
	"regexp"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/snowzach/rotatefilehook"
)

type genericHook struct {
	levels []Level
	fire   func(Entry) error
}

func (g *genericHook) Levels() []Level {
	return g.levels
}

func (g *genericHook) Fire(entry Entry) error {
	return g.fire(entry)
}

func NewHook(levels []Level, fire func(Entry) error) Hook {
	return &genericHook{
		levels: levels,
		fire:   fire,
	}
}

// BackgroundHook is a logrus Hook that (synchronously) formats each log and sends it to one or more
// Destinations for writing on a background thread.  It supports filtering destinations on
// individual log levels.  We write logs from background threads so that blocking of the output
// stream doesn't block the mainline code.  Up to a point, we queue logs for writing, then we start
// dropping logs.
type BackgroundHook struct {
	levels          []Level
	syslogLevel     Level
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

func NewBackgroundHook(
	levels []Level,
	syslogLevel Level,
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

func (h *BackgroundHook) Levels() []Level {
	return h.levels
}

func (h *BackgroundHook) Fire(entry Entry) (err error) {
	if entry.buffer() != nil {
		defer entry.buffer().Truncate(0)
	}

	if entry.GetLevel() >= DebugLevel && h.debugFileNameRE != nil {
		// This is a debug log, check if debug logging is enabled for this file.
		fileName, _ := getFileInfo(entry)
		if fileName == FileNameUnknown || !h.debugFileNameRE.MatchString(fileName) {
			return nil
		}
	}

	var serialized []byte
	if serialized, err = entry.Logger().GetFormatter().Format(entry); err != nil {
		return
	}

	// entry's buffer will be reused after we return but we're about to send the message over
	// a channel so we need to take a copy.
	bufCopy := make([]byte, len(serialized))
	copy(bufCopy, serialized)

	ql := QueuedLog{
		Level:   entry.GetLevel(),
		Message: bufCopy,
	}

	if entry.GetLevel() <= h.syslogLevel {
		// syslog gets its own log string since our default log string duplicates a lot of
		// syslog metadata.  Only calculate that string if it's needed.
		ql.SyslogMessage = FormatForSyslog(entry)
	}

	var waitGroup *sync.WaitGroup
	if entry.GetLevel() <= FatalLevel || entry.Fields()[FieldForceFlush] == true {
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

type hookAdaptor struct {
	Hook
}

func (adaptor *hookAdaptor) Levels() []logrus.Level {
	var levels []logrus.Level
	for _, level := range adaptor.Hook.Levels() {
		levels = append(levels, logrus.Level(level))
	}
	return levels
}

func (adaptor *hookAdaptor) Fire(e *logrus.Entry) error {
	return adaptor.Hook.Fire(&entry{e})
}

type logrusHookWrapper struct {
	logrus.Hook
}

func (l *logrusHookWrapper) Levels() []Level {
	var r []Level
	for _, level := range l.Hook.Levels() {
		r = append(r, Level(level))
	}
	return r
}

func (l *logrusHookWrapper) Fire(e Entry) error {
	return l.Hook.Fire(e.(*entry).entry)
}

func NewRotateFileHook(
	filename string,
	maxSize int,
	maxAge int,
	maxBackups int,
	level Level,
	formatter Formatter,
) (Hook, error) {
	hook, err := rotatefilehook.NewRotateFileHook(rotatefilehook.RotateFileConfig{
		Filename:   filename,
		MaxSize:    maxSize,
		MaxAge:     maxAge,
		MaxBackups: maxBackups,
		Level:      logrus.Level(level),
		Formatter:  &formatterAdaptor{formatter},
	})
	return &logrusHookWrapper{hook}, err
}
