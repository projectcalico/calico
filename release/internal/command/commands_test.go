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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestRealCommandRunnerRun(t *testing.T) {
	r := &RealCommandRunner{}

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

	t.Run("failure keeps stdout and stderr", func(t *testing.T) {
		_, err := r.Run("sh", []string{"-c", "echo the real reason; echo on stderr >&2; exit 3"})
		var cmdErr *Error
		if !errors.As(err, &cmdErr) {
			t.Fatalf("got %v, want *Error", err)
		}
		if cmdErr.Stdout != "the real reason" || cmdErr.Stderr != "on stderr" {
			t.Errorf("got stdout %q stderr %q", cmdErr.Stdout, cmdErr.Stderr)
		}
		for _, want := range []string{"exit status 3", "on stderr", "the real reason"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not contain %q", err, want)
			}
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

	t.Run("failure already streamed leaves stdout out", func(t *testing.T) {
		err := &Error{Stdout: "the real reason", Err: errors.New("exit status 1"), streamed: true}
		if strings.Contains(err.Error(), "the real reason") {
			t.Errorf("error %q repeats stdout that was already streamed", err)
		}
	})
}

func TestRecorder(t *testing.T) {
	t.Run("records each command with its options", func(t *testing.T) {
		var r Recorder
		if _, err := r.Run("make", []string{"build"}, WithDir("/src"), WithEnv("A=B"), WithLogFile("/logs/build.log")); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if _, err := r.Run("git", []string{"status"}); err != nil {
			t.Fatalf("Run: %v", err)
		}
		want := []Call{
			{Name: "make", Args: []string{"build"}, Dir: "/src", Env: []string{"A=B"}, LogFile: "/logs/build.log"},
			{Name: "git", Args: []string{"status"}},
		}
		if diff := cmp.Diff(want, r.Calls()); diff != "" {
			t.Errorf("calls (-want +got):\n%s", diff)
		}
	})

	t.Run("reply gives the output and error", func(t *testing.T) {
		boom := errors.New("boom")
		r := Recorder{Reply: func(c Call) (string, error) {
			if c.Dir == "/fail" {
				return "", boom
			}
			return c.Name + " ran", nil
		}}
		if out, err := r.Run("git", []string{"status"}); out != "git ran" || err != nil {
			t.Errorf("Run = %q, %v; want %q, nil", out, err, "git ran")
		}
		if _, err := r.Run("git", []string{"status"}, WithDir("/fail")); !errors.Is(err, boom) {
			t.Errorf("Run error = %v, want %v", err, boom)
		}
		if got := len(r.Calls()); got != 2 {
			t.Errorf("recorded %d calls, want 2", got)
		}
	})
}

func TestRunner(t *testing.T) {
	t.Run("nil runs real commands", func(t *testing.T) {
		if _, ok := Runner(nil).(*RealCommandRunner); !ok {
			t.Errorf("Runner(nil) = %T, want *RealCommandRunner", Runner(nil))
		}
	})
	t.Run("keeps a given runner", func(t *testing.T) {
		r := &Recorder{}
		if got := Runner(r); got != r {
			t.Errorf("Runner(r) = %v, want r", got)
		}
	})
}
