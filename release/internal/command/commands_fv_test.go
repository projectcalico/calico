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

//go:build fv

package command

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRealRunner(t *testing.T) {
	r := RealRunner

	t.Run("log file gets stdout and stderr", func(t *testing.T) {
		logPath := filepath.Join(t.TempDir(), "subdir", "out.log")
		out, err := r.Run("sh", []string{"-c", "echo hello && echo world >&2"}, WithLogFile(logPath))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if out != "hello" {
			t.Errorf("captured stdout: got %q, want %q", out, "hello")
		}
		data, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatalf("read log file: %v", err)
		}
		for _, want := range []string{"hello", "world"} {
			if !strings.Contains(string(data), want) {
				t.Errorf("log file missing %q; got %q", want, data)
			}
		}
	})

	t.Run("runs in dir with env", func(t *testing.T) {
		dir := t.TempDir()
		out, err := r.Run("sh", []string{"-c", "echo $(pwd) $FOO"}, WithDir(dir), WithEnv("FOO=bar"))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if want := dir + " bar"; out != want {
			t.Errorf("got %q, want %q", out, want)
		}
	})

	t.Run("env adds to the parent's environment", func(t *testing.T) {
		t.Setenv("FROM_PARENT", "kept")
		t.Setenv("FOO", "old")
		out, err := r.Run("sh", []string{"-c", "echo $FROM_PARENT $FOO"}, WithEnv("FOO=new"))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if want := "kept new"; out != want {
			t.Errorf("got %q, want %q", out, want)
		}
	})

	t.Run("a later env option wins on the same key", func(t *testing.T) {
		out, err := r.Run("sh", []string{"-c", "echo $A"}, WithEnv("A=1"), WithEnv("A=4"))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if out != "4" {
			t.Errorf("got %q, want 4", out)
		}
	})

	t.Run("failure keeps stdout and stderr", func(t *testing.T) {
		_, err := r.Run("sh", []string{"-c", "echo the real reason; echo on stderr >&2; exit 3"})
		var cmdErr *Error
		if !errors.As(err, &cmdErr) {
			t.Fatalf("got %v, want *Error", err)
		}
		if cmdErr.Stdout != "the real reason" || cmdErr.Stderr != "on stderr" {
			t.Errorf("got stdout %q stderr %q", cmdErr.Stdout, cmdErr.Stderr)
		}
		if cmdErr.ExitCode != 3 {
			t.Errorf("code = %d, want 3", cmdErr.ExitCode)
		}
		for _, want := range []string{"exit status 3", "on stderr", "the real reason"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not contain %q", err, want)
			}
		}
	})

	t.Run("streamed failure leaves stdout out of the error", func(t *testing.T) {
		_, err := r.Run("sh", []string{"-c", "echo already shown; exit 1"}, WithStream())
		if err == nil {
			t.Fatal("expected an error")
		}
		if strings.Contains(err.Error(), "already shown") {
			t.Errorf("error %q repeats stdout that was already streamed", err)
		}
	})

	t.Run("failure without stdout does not mention it", func(t *testing.T) {
		_, err := r.Run("sh", []string{"-c", "echo on stderr >&2; exit 1"})
		if err == nil {
			t.Fatal("expected an error")
		}
		if strings.Contains(err.Error(), "stdout") {
			t.Errorf("error %q mentions stdout although the command printed none", err)
		}
	})

	t.Run("failure shows only the tail of stdout", func(t *testing.T) {
		_, err := r.Run("sh", []string{"-c", "for i in $(seq 1 100); do echo line $i; done; exit 1"})
		if err == nil {
			t.Fatal("expected an error")
		}
		msg := err.Error()
		if strings.Contains(msg, "line 50\n") || !strings.Contains(msg, "line 51\n") || !strings.HasSuffix(msg, "line 100") {
			t.Errorf("error does not hold exactly the last %d lines: %q", errorStdoutLines, msg)
		}
	})
}
