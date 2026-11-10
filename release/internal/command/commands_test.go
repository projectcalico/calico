// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package command

import (
	"fmt"
	"strings"
	"testing"
)

func TestRunInDirErrorIncludesStdout(t *testing.T) {
	r := &RealCommandRunner{}
	_, err := r.RunInDir("", "sh", []string{"-c", "echo the real reason; echo on stderr >&2; exit 3"}, nil)
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"exit status 3", "on stderr", "the real reason"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestRunInDirErrorWithoutStdout(t *testing.T) {
	r := &RealCommandRunner{}
	_, err := r.RunInDir("", "sh", []string{"-c", "echo on stderr >&2; exit 1"}, nil)
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "stdout") {
		t.Errorf("error %q mentions stdout although the command printed none", err)
	}
}

func TestLastLines(t *testing.T) {
	var b strings.Builder
	for i := 1; i <= 100; i++ {
		fmt.Fprintf(&b, "line %d\n", i)
	}
	got := strings.Split(lastLines(b.String(), 3), "\n")
	want := []string{"line 98", "line 99", "line 100"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("lastLines = %v, want %v", got, want)
	}
	if got := lastLines("  \n", 3); got != "" {
		t.Errorf("lastLines of blank input = %q, want empty", got)
	}
}
