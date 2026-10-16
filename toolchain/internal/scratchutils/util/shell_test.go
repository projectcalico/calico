// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
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

package util

import (
	"os/exec"
	"strings"
	"testing"
)

// The output is sourced by bash on the VM, so the contract is a byte-for-byte
// round trip through a shell. Ask a shell.
func TestShellQuoteRoundTripsThroughBash(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	for _, val := range []string{
		"plain",
		"with space",
		"it's",
		`double"quote`,
		"$(rm -rf /)",
		"`backtick`",
		"semi; echo pwned",
		`back\slash`,
		"new\nline",
		"tab\there",
		"*glob*",
		"${VAR}",
		"",
		"''",
		`'\''`,
	} {
		script := "printf %s " + ShellQuote(val)
		out, err := exec.Command("bash", "-c", script).Output()
		if err != nil {
			t.Errorf("bash rejected quoting of %q: %v", val, err)
			continue
		}
		if string(out) != val {
			t.Errorf("round trip of %q gave %q", val, out)
		}
	}
}

// The env file is `export NAME=<quoted>` lines; a hostile value must not break out
// of the assignment.
func TestShellQuoteInExportLine(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	evil := "x'; touch /tmp/pwned-by-runonvm; echo '"
	script := "export EVIL=" + ShellQuote(evil) + "\nprintf %s \"$EVIL\""
	out, err := exec.Command("bash", "-c", script).Output()
	if err != nil {
		t.Fatalf("bash rejected the export line: %v", err)
	}
	if string(out) != evil {
		t.Fatalf("value did not survive the export line: got %q, want %q", out, evil)
	}
	if strings.Contains(script, "\ntouch") {
		t.Fatal("quoting let the payload escape onto its own line")
	}
}

// A name is interpolated bare into `export NAME=...`, so anything that is not a
// plain identifier can break out of the assignment when the file is sourced.
func TestCheckShellName(t *testing.T) {
	for _, ok := range []string{"FOO", "foo", "_foo", "FOO_BAR", "F1", "_", "a1_B2"} {
		if err := CheckShellName(ok); err != nil {
			t.Errorf("CheckShellName(%q) rejected a valid name: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", "1FOO", "FOO-BAR", "FOO BAR", "FOO;rm -rf /", "FOO=bar", "FOO$X",
		"FOO\nBAR", "$(id)", "FOO.BAR", "foo/bar",
	} {
		if err := CheckShellName(bad); err == nil {
			t.Errorf("CheckShellName(%q) accepted an injectable name", bad)
		}
	}
}

// The reason ShellQuote exists: fmt %q is double-quoted, and bash expands $(...)
// inside double quotes. Prove single quoting does not.
func TestShellQuoteBlocksCommandSubstitution(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	for _, payload := range []string{"/tmp/x$(id -u)", "/tmp/`id -u`", "/tmp/${HOME}"} {
		out, err := exec.Command("bash", "-c", "printf %s "+ShellQuote(payload)).Output()
		if err != nil {
			t.Errorf("bash rejected %q: %v", payload, err)
			continue
		}
		if string(out) != payload {
			t.Errorf("payload was expanded: %q became %q", payload, out)
		}
	}
}
