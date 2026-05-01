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

// Package defaults exposes flag-default values sourced from the repo's
// build metadata. Values resolve once per process via sync.OnceValue.
package defaults

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
)

// driverPrefix snapshots the variables defined before metadata.mk is
// included; driverSuffix prints only those introduced by the include.
const (
	driverPrefix = "VARS_OLD := $(.VARIABLES)\n"
	driverSuffix = "\n_defaults_print:\n" +
		"\t@$(foreach v,$(filter-out $(VARS_OLD) VARS_OLD,$(.VARIABLES)),$(info $(v) = $($(v))))\n"
)

// driverLine matches a `KEY = VALUE` line emitted by the driver's $(info).
var driverLine = regexp.MustCompile(`^([A-Z_][A-Z0-9_]*)\s*=\s*(.*)$`)

const (
	KeyOrganization         = "ORGANIZATION"
	KeyGitRepo              = "GIT_REPO"
	KeyGitRemote            = "GIT_REMOTE"
	KeyReleaseBranchPrefix  = "RELEASE_BRANCH_PREFIX"
	KeyDevTagSuffix         = "DEV_TAG_SUFFIX"
	KeyOperatorBranch       = "OPERATOR_BRANCH"
	KeyOperatorOrganization = "OPERATOR_ORGANIZATION"
	KeyOperatorGitRepo      = "OPERATOR_GIT_REPO"
)

var load = sync.OnceValue(readMetadata)

func readMetadata() map[string]string {
	if len(embeddedMetadata) > 0 {
		m, err := parseMetadata(embeddedMetadata)
		if err != nil {
			logrus.WithError(err).Warn("Failed to parse embedded metadata.mk; release flag defaults will be empty")
			return map[string]string{}
		}
		return m
	}
	root, err := command.GitDir()
	if err != nil {
		logrus.WithError(err).Warn("Failed to locate git root for metadata.mk; release flag defaults will be empty")
		return map[string]string{}
	}
	data, err := os.ReadFile(filepath.Join(root, "metadata.mk"))
	if err != nil {
		logrus.WithError(err).Warn("Failed to read metadata.mk; release flag defaults will be empty")
		return map[string]string{}
	}
	m, err := parseMetadata(data)
	if err != nil {
		logrus.WithError(err).Warn("Failed to parse metadata.mk; release flag defaults will be empty")
		return map[string]string{}
	}
	return m
}

// parseMetadata wraps data with a driver makefile and runs make on it via
// stdin, so make resolves $(...) references and ?= precedence naturally.
// The driver prints only the variables introduced by the included data.
func parseMetadata(data []byte) (map[string]string, error) {
	var stdin bytes.Buffer
	stdin.WriteString(driverPrefix)
	stdin.Write(data)
	stdin.WriteString(driverSuffix)

	cmd := exec.Command("make", "--quiet", "-f", "-", "_defaults_print")
	cmd.Stdin = &stdin
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("make: %w: %s", err, out)
	}
	return parseDriverOutput(string(out))
}

// parseDriverOutput reads the driver's $(info) output (one `KEY = VALUE` per
// line) and returns the assignments.
func parseDriverOutput(out string) (map[string]string, error) {
	m := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewBufferString(out))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		match := driverLine.FindStringSubmatch(scanner.Text())
		if match == nil {
			continue
		}
		m[match[1]] = strings.TrimSpace(match[2])
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning driver output: %w", err)
	}
	return m, nil
}

func get(key string) string { return load()[key] }

func Organization() string         { return get(KeyOrganization) }
func Repo() string                 { return get(KeyGitRepo) }
func Remote() string               { return get(KeyGitRemote) }
func ReleaseBranchPrefix() string  { return get(KeyReleaseBranchPrefix) }
func DevTagSuffix() string         { return get(KeyDevTagSuffix) }
func OperatorBranch() string       { return get(KeyOperatorBranch) }
func OperatorOrganization() string { return get(KeyOperatorOrganization) }
func OperatorRepo() string         { return get(KeyOperatorGitRepo) }
