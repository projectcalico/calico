// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package utils

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/projectcalico/calico/release/internal/command"
)

const (
	// DefaultBranch is the default branch of the repository.
	DefaultBranch = "master"
)

// Clone clones the repository at the given branch as the given directory.
func Clone(repo, branch, dir string) error {
	parentDir := filepath.Dir(dir)
	if err := os.MkdirAll(parentDir, DirPerms); err != nil {
		return err
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		_, err := command.GitInDir(dir, "checkout", branch)
		if err == nil {
			_, err = command.GitInDir(dir, "pull")
			return err
		}
	}
	_, err := command.GitInDir(parentDir, "clone", repo, "--branch", branch, filepath.Base(dir))
	return err
}

// GitBranch returns the current git branch of the repository.
func GitBranch(dir string) (string, error) {
	return command.GitInDir(dir, "rev-parse", "--abbrev-ref", "HEAD")
}

// GitIsDirty returns true if the repository is dirty.
func GitIsDirty(dir string) (bool, error) {
	version, err := command.GitVersion(dir, true)
	if err != nil {
		return false, err
	}
	return strings.HasSuffix(version, "-dirty"), nil
}
