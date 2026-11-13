// Copyright (c) 2026 Tigera, Inc. All rights reserved.

// Package logging holds logrus helpers shared by the release tooling.
package logging

import (
	"bytes"
	"fmt"
	"hash/fnv"
	"maps"
	"strings"

	"github.com/sirupsen/logrus"
)

// ErrorIDKey is the field that tags an entry whose error was split across lines.
const ErrorIDKey = "error_id"

// MultilineErrorFormatter keeps multi-line errors readable. logrus's TextFormatter quotes
// field values and escapes their newlines, which turns command output carried in an error
// into one long line full of "\n". This leaves the first line of the error in the entry,
// tags the entry with a short ID, and writes the remaining lines after it unescaped, each
// prefixed with that ID so the whole error can be found with a single grep.
type MultilineErrorFormatter struct {
	logrus.Formatter
}

func (f *MultilineErrorFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	err, ok := entry.Data[logrus.ErrorKey].(error)
	if !ok || err == nil {
		return f.Formatter.Format(entry)
	}
	lines := strings.Split(strings.TrimSpace(err.Error()), "\n")
	if len(lines) < 2 {
		return f.Formatter.Format(entry)
	}
	id := errorID(entry, err.Error())

	// Format a copy, so the other formatters (terminal and log file) still see the full error.
	e := *entry
	e.Buffer = nil
	e.Data = make(logrus.Fields, len(entry.Data)+1)
	maps.Copy(e.Data, entry.Data)
	e.Data[logrus.ErrorKey] = strings.TrimSpace(lines[0])
	e.Data[ErrorIDKey] = id

	out, fmtErr := f.Formatter.Format(&e)
	if fmtErr != nil {
		return nil, fmtErr
	}
	b := bytes.NewBuffer(out)
	for _, line := range lines[1:] {
		fmt.Fprintf(b, "  %s| %s\n", id, line)
	}
	return b.Bytes(), nil
}

// errorID derives a short ID from the entry rather than picking one at random, so that the
// terminal and the log file, which format the same entry separately, show the same ID.
func errorID(entry *logrus.Entry, errText string) string {
	h := fnv.New32a()
	_, _ = fmt.Fprintf(h, "%d\x00%s\x00%s", entry.Time.UnixNano(), entry.Message, errText)
	return fmt.Sprintf("%06x", h.Sum32()&0xffffff)
}
