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

package calico

import (
	"os"
	"testing"
)

// The tests run git in temp repos. A build container started from a git
// worktree sets GIT_DIR and GIT_WORK_TREE, which would point that git at the
// checkout's own, read-only, repository instead.
func TestMain(m *testing.M) {
	_ = os.Unsetenv("GIT_DIR")
	_ = os.Unsetenv("GIT_WORK_TREE")
	os.Exit(m.Run())
}
