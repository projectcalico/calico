// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.

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

package common

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestExecDoesNotLogArguments(t *testing.T) {
	var output bytes.Buffer
	logger := log.StandardLogger()
	oldOutput, oldLevel := logger.Out, logger.GetLevel()
	logger.SetOutput(&output)
	logger.SetLevel(log.DebugLevel)
	t.Cleanup(func() { logger.SetOutput(oldOutput); logger.SetLevel(oldLevel) })
	result, err := ExecCmd("echo test-secret")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "test-secret") {
		t.Fatal("command argument leaked into logs")
	}
	if !strings.Contains(result.String(), "test-secret") {
		t.Fatal("command argument changed")
	}
}
func TestDiagnosticOutputSanitizedBeforeWriting(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input")
	out := filepath.Join(dir, "output")
	if err := os.WriteFile(input, []byte("test-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := Cmd{CmdStr: "cat " + input, FilePath: out, SanitizeOutput: func(data []byte) ([]byte, error) {
		return bytes.ReplaceAll(data, []byte("test-secret"), []byte("censored")), nil
	}}
	ExecCmdWriteToFile("test", cmd)
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "censored" {
		t.Fatal("unsanitized diagnostic saved")
	}
	cmd.FilePath = filepath.Join(dir, "rejected")
	cmd.SanitizeOutput = func([]byte) ([]byte, error) { return nil, fmt.Errorf("cannot sanitize") }
	ExecCmdWriteToFile("test", cmd)
	if _, err := os.Stat(cmd.FilePath); !os.IsNotExist(err) {
		t.Fatal("sanitizer failure should not persist output")
	}
}
