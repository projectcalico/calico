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
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestError(t *testing.T) {
	t.Run("already streamed leaves stdout out", func(t *testing.T) {
		err := &Error{Stdout: "the real reason", Err: errors.New("exit status 1"), streamed: true}
		if strings.Contains(err.Error(), "the real reason") {
			t.Errorf("error %q repeats stdout that was already streamed", err)
		}
	})
}

func TestRecorder(t *testing.T) {
	t.Run("records each command with its options", func(t *testing.T) {
		var r Recorder
		if _, err := r.Run("make", []string{"build"}, WithDir("/src"), WithEnv("A=B"), WithLogFile("/logs/build.log"), WithStream()); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if _, err := r.Run("git", []string{"status"}); err != nil {
			t.Fatalf("Run: %v", err)
		}
		want := []Call{
			{Name: "make", Args: []string{"build"}, Dir: "/src", Env: []string{"A=B"}, LogFile: "/logs/build.log", Stream: true},
			{Name: "git", Args: []string{"status"}},
		}
		if diff := cmp.Diff(want, r.Calls()); diff != "" {
			t.Errorf("calls (-want +got):\n%s", diff)
		}
	})

	t.Run("nil options are skipped", func(t *testing.T) {
		var r Recorder
		if _, err := r.Run("git", []string{"status"}, nil, WithDir("/src"), nil); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if diff := cmp.Diff([]Call{{Name: "git", Args: []string{"status"}, Dir: "/src"}}, r.Calls()); diff != "" {
			t.Errorf("calls (-want +got):\n%s", diff)
		}
	})

	t.Run("env options add up", func(t *testing.T) {
		var r Recorder
		if _, err := r.Run("make", nil, WithEnv("A=1"), WithEnv("B=2", "A=4")); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if diff := cmp.Diff([]string{"A=1", "B=2", "A=4"}, r.Calls()[0].Env); diff != "" {
			t.Errorf("env (-want +got):\n%s", diff)
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
		if _, ok := Runner(nil).(*realCommandRunner); !ok {
			t.Errorf("Runner(nil) = %T, want *realCommandRunner", Runner(nil))
		}
	})
	t.Run("keeps a given runner", func(t *testing.T) {
		r := &Recorder{}
		if got := Runner(r); got != r {
			t.Errorf("Runner(r) = %v, want r", got)
		}
	})
}
