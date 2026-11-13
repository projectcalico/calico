// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package command

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunInDirToFile(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "subdir", "out.log")

	r := &RealCommandRunner{}
	out, err := r.RunInDirToFile("", "sh", []string{"-c", "echo hello && echo world >&2"}, nil, logPath)
	if err != nil {
		t.Fatalf("RunInDirToFile: %v", err)
	}
	if out != "hello" {
		t.Errorf("captured stdout: got %q, want %q", out, "hello")
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	got := string(data)
	if !strings.Contains(got, "hello") {
		t.Errorf("log file missing stdout line; got %q", got)
	}
	if !strings.Contains(got, "world") {
		t.Errorf("log file missing stderr line; got %q", got)
	}
}

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
