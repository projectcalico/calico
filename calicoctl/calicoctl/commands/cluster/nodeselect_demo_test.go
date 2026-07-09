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

package cluster

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestPickerDemoBuilds guards the build-tagged pickerdemo developer harness
// (nodeselect_demo.go and cmd/pickerdemo) against bit-rot. Because those files
// are excluded from every normal build, nothing else in CI would notice if a
// refactor broke them — so compile them here with the tag set.
func TestPickerDemoBuilds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping pickerdemo build in -short mode")
	}
	out := filepath.Join(t.TempDir(), "pickerdemo")
	cmd := exec.Command("go", "build", "-tags", "pickerdemo", "-o", out,
		"github.com/projectcalico/calico/calicoctl/calicoctl/commands/cluster/cmd/pickerdemo")
	cmd.Env = os.Environ()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("pickerdemo developer harness failed to build with -tags pickerdemo: %v\n%s", err, out)
	}
}
