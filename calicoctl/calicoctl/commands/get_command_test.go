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

package commands

import "testing"

// calicoctl historically treated -a and -A identically for all-namespaces;
// TestMultiOption (calicoctl/tests/fv) locks that in. Cover it here too so a
// regression fails fast at the unit level.
func TestGetAllNamespacesShorthand(t *testing.T) {
	for _, arg := range []string{"-A", "-a"} {
		cmd := newGetCommand()
		if err := cmd.ParseFlags([]string{arg}); err != nil {
			t.Fatalf("parsing %q: %v", arg, err)
		}
		if !allNamespacesRequested(cmd) {
			t.Errorf("%q should select all namespaces", arg)
		}
	}

	cmd := newGetCommand()
	if err := cmd.ParseFlags(nil); err != nil {
		t.Fatalf("parsing no flags: %v", err)
	}
	if allNamespacesRequested(cmd) {
		t.Error("no flag should not select all namespaces")
	}
}
