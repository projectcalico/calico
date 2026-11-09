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

package command

import (
	"slices"
	"strings"
)

// GitInDir runs a git command in a specific directory.
func GitInDir(dir string, args ...string) (string, error) {
	return runner().RunInDir(dir, "git", args, nil)
}

// Git runs a git command.
func Git(args ...string) (string, error) {
	return runner().Run("git", args, nil)
}

func GitVersion(dir string, includeDirty bool) (string, error) {
	args := []string{"describe", "--tags", "--always", "--long", "--abbrev=12"}
	if includeDirty {
		args = append(args, "--dirty")
	}
	return GitInDir(dir, args...)
}

// GitTagPointsAtHead returns true if the given tag exists and points at HEAD in dir.
func GitTagPointsAtHead(dir, tag string) (bool, error) {
	out, err := GitInDir(dir, "tag", "--points-at", "HEAD")
	if err != nil {
		return false, err
	}
	return slices.Contains(strings.Fields(out), tag), nil
}

// GitDir returns the root directory of the git repository.
func GitDir() (string, error) {
	args := []string{"rev-parse", "--show-toplevel"}
	return Git(args...)
}
