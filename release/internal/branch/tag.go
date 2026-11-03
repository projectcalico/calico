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

package branch

import (
	"cmp"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

// tagRefPrefix marks a cut source that is a tag rather than a branch.
const tagRefPrefix = "refs/tags/"

// TagSource returns the cut source for cutting from tagName.
func TagSource(tagName string) string {
	return tagRefPrefix + tagName
}

// checkTagOnRemote verifies tagName exists locally and on remote at the same
// commit. Under report (plan mode) a mismatch is a warning; a failed remote
// query is always an error.
func checkTagOnRemote(g git, tagName, remote string, report bool) error {
	ref := tagRefPrefix + tagName
	// ls-remote lists an annotated tag's peeled commit under "<ref>^{}".
	out, err := g("ls-remote", remote, ref, ref+"^{}")
	if err != nil {
		return fmt.Errorf("checking %s on %s: %w", ref, remote, err)
	}
	problem := tagMismatch(g, tagName, remote, out)
	if problem == nil {
		return nil
	}
	if report {
		logrus.Warnf("%v; a cut will error unless resolved", problem)
		return nil
	}
	return problem
}

// tagMismatch compares the local tag with the remote's, given its ls-remote output.
func tagMismatch(g git, tagName, remote, lsRemote string) error {
	ref := tagRefPrefix + tagName
	local, err := g("rev-parse", "--verify", "--quiet", ref+"^{commit}")
	if err != nil {
		return fmt.Errorf("tag %s does not exist locally; fetch it with `git fetch %s tag %s`", tagName, remote, tagName)
	}
	want := strings.TrimSpace(local)
	commits := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(lsRemote), "\n") {
		if f := strings.Fields(line); len(f) == 2 {
			commits[f[1]] = f[0]
		}
	}
	got := cmp.Or(commits[ref+"^{}"], commits[ref])
	if got == "" {
		return fmt.Errorf("tag %s is not on %s; only a released tag can be cut from", tagName, remote)
	}
	if got != want {
		return fmt.Errorf("local tag %s (%s) does not match %s (%s)", tagName, want, remote, got)
	}
	return nil
}
