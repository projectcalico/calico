// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"slices"
	"testing"
)

// Preflight writes results to <artifacts>/<platform>/, so --artifacts must be
// the image directory or results land in <image>/<platform>/<platform>/.
func TestPreflightCommandArtifactsPaths(t *testing.T) {
	job := scanJob{image: "calico", platform: "arm64", project: "p", workdir: "out/calico/arm64"}
	abs := "/abs/out/calico/arm64"

	for _, tc := range []struct {
		runtime   containerRuntime
		mount     string
		artifacts string
		logfile   string
	}{
		{runtimePodman, "/abs/out/calico:/artifacts", "/artifacts", "/artifacts/arm64/preflight.log"},
		{runtimeDocker, "/abs/out/calico:/artifacts", "/artifacts", "/artifacts/arm64/preflight.log"},
		{runtimeNative, "", "/abs/out/calico", "/abs/out/calico/arm64/preflight.log"},
	} {
		t.Run(string(tc.runtime), func(t *testing.T) {
			_, args := preflightCommand(runOpts{runtime: tc.runtime}, abs, "img", job, "preflight", false)
			if tc.mount != "" {
				if got := flagValue(args, "-v"); got != tc.mount {
					t.Errorf("-v = %q, want %q", got, tc.mount)
				}
			}
			if got := flagValue(args, "--artifacts"); got != tc.artifacts {
				t.Errorf("--artifacts = %q, want %q", got, tc.artifacts)
			}
			if got := flagValue(args, "--logfile"); got != tc.logfile {
				t.Errorf("--logfile = %q, want %q", got, tc.logfile)
			}
		})
	}
}

func flagValue(args []string, flag string) string {
	i := slices.Index(args, flag)
	if i < 0 || i+1 >= len(args) {
		return ""
	}
	return args[i+1]
}
