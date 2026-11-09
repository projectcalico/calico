// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package main

import (
	"bytes"
	"fmt"
	"hash/fnv"
	"strings"

	"github.com/sirupsen/logrus"
)

const errorIDKey = "error_id"

// multilineErrorFormatter keeps multi-line errors readable. logrus's TextFormatter quotes
// field values and escapes their newlines, which turns command output carried in an error
// into one long line full of "\n". This leaves the first line of the error in the entry,
// tags the entry with a short ID, and writes the remaining lines after it unescaped, each
// prefixed with that ID so the whole error can be found with a single grep.
type multilineErrorFormatter struct {
	logrus.Formatter
}

func (f *multilineErrorFormatter) Format(entry *logrus.Entry) ([]byte, error) {
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
	for k, v := range entry.Data {
		e.Data[k] = v
	}
	e.Data[logrus.ErrorKey] = strings.TrimSpace(lines[0])
	e.Data[errorIDKey] = id

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
