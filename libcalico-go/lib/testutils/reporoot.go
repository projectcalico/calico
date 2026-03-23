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

package testutils

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

// FindRepoRoot walks up from the current working directory to find the calico
// monorepo root (the directory containing go.mod with module github.com/projectcalico/calico).
// This is useful for test binaries that may run from a different working directory
// than the source package, and need to locate CRDs or other repo-relative files.
// Panics if the root cannot be found.
func FindRepoRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		panic(fmt.Sprintf("cannot get working directory: %v", err))
	}
	for {
		gomod := filepath.Join(dir, "go.mod")
		if data, err := os.ReadFile(gomod); err == nil {
			if bytes.Contains(data, []byte("module github.com/projectcalico/calico\n")) ||
				bytes.Contains(data, []byte("module github.com/projectcalico/calico\r\n")) {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			panic("cannot find calico monorepo root (go.mod with module github.com/projectcalico/calico)")
		}
		dir = parent
	}
}
