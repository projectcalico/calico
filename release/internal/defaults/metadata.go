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

// Package defaults holds the per-repo values the release tool defaults to,
// read from the repo's build metadata. Values resolve once per process.
//
// Constant names match metadata.mk variable names verbatim. Unknown keys
// resolve to empty, so additional keys are added by adding a constant and
// a metadata.mk entry.
package defaults

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
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
	KeyOrganization        = "ORGANIZATION"
	KeyGitRepo             = "GIT_REPO"
	KeyGitRemote           = "GIT_REMOTE"
	KeyReleaseBranchPrefix = "RELEASE_BRANCH_PREFIX"
	KeyDevTagSuffix        = "DEV_TAG_SUFFIX"
)

const MetadataFile = "metadata.mk"

var (
	runner command.CommandRunner
	load   = sync.OnceValue(readMetadata)
)

// UseRunner sets the runner that reads metadata.mk; nil reads it for real.
func UseRunner(r command.CommandRunner) {
	runner = r
	load = sync.OnceValue(readMetadata)
}

func readMetadata() map[string]string {
	if len(embeddedMetadata) > 0 {
		m, err := parseMetadata(embeddedMetadata)
		if err != nil {
			logrus.WithError(err).Warn("Failed to parse embedded metadata.mk; release flag defaults will be empty")
			return map[string]string{}
		}
		return m
	}
	root, err := command.Git(command.Runner(runner)).RepoRoot()
	if err != nil {
		logrus.WithError(err).Warn("Failed to locate git root for metadata.mk; release flag defaults will be empty")
		return map[string]string{}
	}
	data, err := os.ReadFile(filepath.Join(root, MetadataFile))
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
	out, err := command.Make(command.Runner(runner), "").Run([]string{"--quiet", "-f", "-", "_defaults_print"}, command.WithStdin(driverPrefix+string(data)+driverSuffix))
	if err != nil {
		return nil, fmt.Errorf("make: %w", err)
	}
	return parseDriverOutput(out)
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

var builtin = map[string]*string{
	KeyOrganization:        &organization,
	KeyGitRepo:             &repo,
	KeyGitRemote:           &remote,
	KeyReleaseBranchPrefix: &releaseBranchPrefix,
	KeyDevTagSuffix:        &devTagSuffix,
}

// Builtin is key's value when metadata.mk does not set it. It reads no
// metadata, so it is safe to call at package init.
func Builtin(key string) string {
	if v, ok := builtin[key]; ok {
		return *v
	}
	return ""
}

func value(key string) string {
	if v := load()[key]; v != "" {
		return v
	}
	return Builtin(key)
}

func Organization() string        { return value(KeyOrganization) }
func Repo() string                { return value(KeyGitRepo) }
func Remote() string              { return value(KeyGitRemote) }
func ReleaseBranchPrefix() string { return value(KeyReleaseBranchPrefix) }
func DevTagSuffix() string        { return value(KeyDevTagSuffix) }
