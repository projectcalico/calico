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

//go:build fv

package command

import (
	"os"
	"strings"
	"testing"
)

func TestGitIgnoresNonVersionTags(t *testing.T) {
	// A config that signs every tag would turn these lightweight tags into
	// annotated ones, which need a message and a tagger.
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	dir := t.TempDir()
	g := Git(RealRunner).In(dir)
	for _, args := range [][]string{
		{"init", "-q", "-b", "master"},
		{"-c", "user.email=ci@example.com", "-c", "user.name=ci", "commit", "-q", "--allow-empty", "-m", "one"},
		{"tag", "v3.0.0"},
		{"-c", "user.email=ci@example.com", "-c", "user.name=ci", "commit", "-q", "--allow-empty", "-m", "two"},
		// None of these is a version: another component's release, a project
		// whose name starts with "v", and a version with no patch.
		{"tag", "cc-operator-v3.0.1"},
		{"tag", "vpn-v1.2.0"},
		{"tag", "v3.1"},
	} {
		if _, err := g.Run(args...); err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
	}

	version, err := g.Version(false)
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if !strings.HasPrefix(version, "v3.0.0-1-g") {
		t.Errorf("Version = %q, want it described from v3.0.0, not a non-version tag on HEAD", version)
	}

	latest, err := g.LatestTag("master")
	if err != nil {
		t.Fatalf("LatestTag: %v", err)
	}
	if latest != "v3.0.0" {
		t.Errorf("LatestTag = %q, want v3.0.0", latest)
	}
}
