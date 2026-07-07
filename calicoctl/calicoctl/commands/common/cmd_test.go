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

package common_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/common"
)

// collector returns a Collector with a generous inactivity timeout, for tests
// that don't care about timing out.
func collector() *common.Collector {
	return common.NewCollector(context.Background(), 30*time.Second, 1)
}

// TestExecWriteToFile_Fallback verifies that when the primary command exits
// non-zero and a fallback is configured, the fallback output is collected into
// the fallback file and the primary file is not written. This is what keeps
// diags useful against an older component (e.g. --json unsupported -> retry
// without it and keep the plain-text output).
func TestExecWriteToFile_Fallback(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "out.json")
	txtPath := filepath.Join(dir, "out.txt")

	collector().ExecAllWriteToFile([]common.Cmd{{
		CmdStr:           "false", // exits non-zero
		FilePath:         jsonPath,
		FallbackCmdStr:   "echo fellback", // succeeds
		FallbackFilePath: txtPath,
	}})

	if _, err := os.Stat(jsonPath); !os.IsNotExist(err) {
		t.Fatalf("expected primary file %s not to be written, stat err=%v", jsonPath, err)
	}
	got, err := os.ReadFile(txtPath)
	if err != nil {
		t.Fatalf("reading fallback file: %v", err)
	}
	if strings.TrimSpace(string(got)) != "fellback" {
		t.Fatalf("unexpected fallback content: %q", got)
	}
}

// TestExecWriteToFile_PrimarySucceeds verifies the fallback is not used when
// the primary command succeeds.
func TestExecWriteToFile_PrimarySucceeds(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "out.json")
	txtPath := filepath.Join(dir, "out.txt")

	collector().ExecAllWriteToFile([]common.Cmd{{
		CmdStr:           "echo primary",
		FilePath:         jsonPath,
		FallbackCmdStr:   "echo fellback",
		FallbackFilePath: txtPath,
	}})

	got, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("reading primary file: %v", err)
	}
	if strings.TrimSpace(string(got)) != "primary" {
		t.Fatalf("unexpected primary content: %q", got)
	}
	if _, err := os.Stat(txtPath); !os.IsNotExist(err) {
		t.Fatalf("fallback file should not exist when primary succeeds")
	}
}

// TestExecWriteToFile_NoOutputTimeout verifies a command that produces no output
// for the inactivity timeout is killed, recorded, and its output file carries
// the explanatory marker.
func TestExecWriteToFile_NoOutputTimeout(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.txt")

	coll := common.NewCollector(context.Background(), 200*time.Millisecond, 1)
	start := time.Now()
	coll.ExecAllWriteToFile([]common.Cmd{{
		CmdStr:   "sleep 30",
		FilePath: out,
	}})
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("command was not killed promptly: took %s", elapsed)
	}

	timedOut := coll.TimedOut()
	if len(timedOut) != 1 || timedOut[0].Command != "sleep 30" {
		t.Fatalf("expected one recorded timeout for 'sleep 30', got %+v", timedOut)
	}

	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}
	if !strings.Contains(string(got), "command killed") {
		t.Fatalf("output file missing timeout marker: %q", got)
	}
}

// TestExec_OutputResetsTimer verifies that a command producing output more often
// than the inactivity timeout is not killed. The script is passed as a single
// token so it survives without shell-quote parsing.
func TestExec_OutputResetsTimer(t *testing.T) {
	coll := common.NewCollector(context.Background(), 500*time.Millisecond, 1)
	buf, err := coll.Exec([]string{"sh", "-c", "for i in 1 2 3; do echo x; sleep 0.1; done"})
	if err != nil {
		t.Fatalf("command should have completed, got err: %v", err)
	}
	if strings.Count(buf.String(), "x") != 3 {
		t.Fatalf("unexpected output: %q", buf.String())
	}
	if n := len(coll.TimedOut()); n != 0 {
		t.Fatalf("expected no timeouts, got %d", n)
	}
}

// TestExec_CancelledContextShortCircuits verifies that once the collection
// context is cancelled, no command is started.
func TestExec_CancelledContextShortCircuits(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	coll := common.NewCollector(ctx, 30*time.Second, 1)

	dir := t.TempDir()
	out := filepath.Join(dir, "out.txt")
	// This would create the file if it ran; it must not.
	coll.ExecAllWriteToFile([]common.Cmd{{CmdStr: "echo hi", FilePath: out}})
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("expected no output file when context is cancelled, stat err=%v", err)
	}

	if _, err := coll.Exec([]string{"echo", "hi"}); err == nil {
		t.Fatalf("expected error from Exec on cancelled context")
	}
}
