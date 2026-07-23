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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/common"
)

// TestExecCmdWriteToFile_Fallback verifies that when the primary command exits
// non-zero and a fallback is configured, the fallback output is collected into
// the fallback file and the primary file is not written. This is what keeps
// diags useful against an older component (e.g. --json unsupported -> retry
// without it and keep the plain-text output).
func TestExecCmdWriteToFile_Fallback(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "out.json")
	txtPath := filepath.Join(dir, "out.txt")

	common.ExecCmdWriteToFile("[test]", common.Cmd{
		CmdStr:           "false", // exits non-zero
		FilePath:         jsonPath,
		FallbackCmdStr:   "echo fellback", // succeeds
		FallbackFilePath: txtPath,
	})

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

// TestExecCmdWriteToFile_EmptyCmd verifies that an empty/whitespace command
// string is handled gracefully rather than panicking on parts[0].
func TestExecCmdWriteToFile_EmptyCmd(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "out.json")

	common.ExecCmdWriteToFile("[test]", common.Cmd{
		CmdStr:   "   ", // whitespace only -> no tokens
		FilePath: jsonPath,
	})

	if _, err := os.Stat(jsonPath); !os.IsNotExist(err) {
		t.Fatalf("expected no output file for an empty command, stat err=%v", err)
	}
}

// TestExecCmdWriteToFile_EmptyFallback verifies that an empty fallback command
// is skipped (not executed) and does not panic when the primary fails.
func TestExecCmdWriteToFile_EmptyFallback(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "out.json")
	txtPath := filepath.Join(dir, "out.txt")

	common.ExecCmdWriteToFile("[test]", common.Cmd{
		CmdStr:           "false", // exits non-zero
		FilePath:         jsonPath,
		FallbackCmdStr:   "   ", // whitespace only -> no tokens
		FallbackFilePath: txtPath,
	})

	if _, err := os.Stat(txtPath); !os.IsNotExist(err) {
		t.Fatalf("expected no fallback file for an empty fallback command, stat err=%v", err)
	}
}

// TestExecCmdWriteToFile_PrimarySucceeds verifies the fallback is not used when
// the primary command succeeds.
func TestExecCmdWriteToFile_PrimarySucceeds(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "out.json")
	txtPath := filepath.Join(dir, "out.txt")

	common.ExecCmdWriteToFile("[test]", common.Cmd{
		CmdStr:           "echo primary",
		FilePath:         jsonPath,
		FallbackCmdStr:   "echo fellback",
		FallbackFilePath: txtPath,
	})

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

// TestExecCmdWriteToFile_OmitIfEmpty_Failed verifies that when OmitIfEmpty is
// set and the command fails, no output file (and no symlink) is written. This
// is the never-restarted-sibling case: `kubectl logs --previous` fails with a
// "not found" message, which we don't want cluttering the bundle.
func TestExecCmdWriteToFile_OmitIfEmpty_Failed(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "pod.sidecar.previous.log")
	linkPath := filepath.Join(dir, "links", "pod.sidecar.previous.log")

	common.ExecCmdWriteToFile("[test]", common.Cmd{
		CmdStr:      "false", // exits non-zero, as `kubectl logs --previous` does for a container with no previous incarnation
		FilePath:    logPath,
		SymLink:     linkPath,
		OmitIfEmpty: true,
	})

	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatalf("expected no output file for a failed OmitIfEmpty command, stat err=%v", err)
	}
	if _, err := os.Lstat(linkPath); !os.IsNotExist(err) {
		t.Fatalf("expected no symlink for a failed OmitIfEmpty command, stat err=%v", err)
	}
}

// TestExecCmdWriteToFile_OmitIfEmpty_EmptyOutput verifies that a command that
// succeeds but produces only whitespace is also omitted when OmitIfEmpty is set.
func TestExecCmdWriteToFile_OmitIfEmpty_EmptyOutput(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "pod.container.previous.log")

	common.ExecCmdWriteToFile("[test]", common.Cmd{
		CmdStr:      "echo   ", // succeeds, output is whitespace only
		FilePath:    logPath,
		OmitIfEmpty: true,
	})

	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatalf("expected no output file for empty OmitIfEmpty output, stat err=%v", err)
	}
}

// TestExecCmdWriteToFile_OmitIfEmpty_NonEmpty verifies that OmitIfEmpty does not
// suppress real output: a crashed container with previous logs is still written.
func TestExecCmdWriteToFile_OmitIfEmpty_NonEmpty(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "pod.crasher.previous.log")

	common.ExecCmdWriteToFile("[test]", common.Cmd{
		CmdStr:      "echo panic: goodbye",
		FilePath:    logPath,
		OmitIfEmpty: true,
	})

	got, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}
	if strings.TrimSpace(string(got)) != "panic: goodbye" {
		t.Fatalf("unexpected content: %q", got)
	}
}
