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
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
)

// makeAssignment matches a make variable assignment line. `!=` is excluded
// on purpose — shell output has no business being a flag default.
var makeAssignment = regexp.MustCompile(`^([A-Z_][A-Z0-9_]*)\s*(?:\?|:{1,3}|\+)?=\s*(.*)$`)

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

func parseMetadata(data []byte) (map[string]string, error) {
	tmp, err := os.CreateTemp("", "metadata-*.mk")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return nil, err
	}
	if _, err := tmp.Write([]byte("\n_defaults_noop:\n")); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	out, err := command.Make([]string{"-f", tmp.Name(), "-pn", "_defaults_noop"}, nil)
	if err != nil {
		return nil, err
	}
	return parseMakeDatabase(out), nil
}

// parseMakeDatabase reads the output of `make -pn` and returns variable
// assignments. Make's database dump emits lines like `KEY = VALUE` for every
// resolved variable; we only retain the keys we care about.
func parseMakeDatabase(out string) map[string]string {
	wanted := map[string]struct{}{
		KeyOrganization:         {},
		KeyGitRepo:              {},
		KeyGitRemote:            {},
		KeyReleaseBranchPrefix:  {},
		KeyDevTagSuffix:         {},
		KeyOperatorBranch:       {},
		KeyOperatorOrganization: {},
		KeyOperatorGitRepo:      {},
	}
	m := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewBufferString(out))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || line[0] == '#' || line[0] == '\t' {
			continue
		}
		match := makeAssignment.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		key := match[1]
		if _, ok := wanted[key]; !ok {
			continue
		}
		m[key] = strings.TrimSpace(match[2])
	}
	return m
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
