// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func formatEntry(t *testing.T, err error) string {
	t.Helper()
	f := &multilineErrorFormatter{&logrus.TextFormatter{DisableColors: true, DisableTimestamp: true}}
	entry := logrus.NewEntry(logrus.New()).WithError(err)
	entry.Time = time.Unix(1700000000, 0)
	entry.Level = logrus.ErrorLevel
	entry.Message = "Error running app"
	out, fmtErr := f.Format(entry)
	if fmtErr != nil {
		t.Fatalf("Format returned error: %v", fmtErr)
	}
	return string(out)
}

func TestMultilineErrorFormatter(t *testing.T) {
	err := errors.New("exit status 2: \nlast 2 lines of stdout:\nMANIFEST_UNKNOWN: manifest unknown")
	out := formatEntry(t, err)

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d:\n%s", len(lines), out)
	}
	if strings.Contains(out, `\n`) {
		t.Errorf("output still contains escaped newlines:\n%s", out)
	}
	if !strings.Contains(lines[0], `error="exit status 2:"`) {
		t.Errorf("first line should carry the first line of the error, got %q", lines[0])
	}

	id := errorID(&logrus.Entry{Time: time.Unix(1700000000, 0), Message: "Error running app"}, err.Error())
	if !strings.Contains(lines[0], "error_id="+id) {
		t.Errorf("first line should carry error_id=%s, got %q", id, lines[0])
	}
	for i, want := range []string{"last 2 lines of stdout:", "MANIFEST_UNKNOWN: manifest unknown"} {
		if got, wantLine := lines[i+1], "  "+id+"| "+want; got != wantLine {
			t.Errorf("line %d = %q, want %q", i+1, got, wantLine)
		}
	}

	// The terminal and log file format the same entry separately and must agree on the ID.
	if again := formatEntry(t, err); again != out {
		t.Errorf("formatting the same entry twice differs:\n%s\n%s", out, again)
	}
}

func TestMultilineErrorFormatterSingleLine(t *testing.T) {
	out := formatEntry(t, errors.New("just one line"))
	if strings.Contains(out, errorIDKey) || strings.Count(out, "\n") != 1 {
		t.Errorf("single-line errors should be formatted unchanged, got:\n%s", out)
	}
}
