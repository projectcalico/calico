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

package command

import (
	"testing"
)

func TestGitRefExistsInRemote(t *testing.T) {
	t.Parallel()
	// Simulated ls-remote output
	lsRemoteOutput := "abc123\trefs/heads/release-v1.43\ndef456\trefs/tags/v3.30\nghi789\trefs/tags/v3.30^{}\njkl012\trefs/heads/release/v1.2"

	tests := []struct {
		ref  string
		want bool
	}{
		{"release-v1.43", true},
		{"v3.30", true},
		{"v3.3", false}, // should not match partial
		{"v3.30^{}", true},
		{"release-v1.4", false},
		{"nonexistent", false},
		{"release/v1.2", true}, // ref with slash
		{"v1.2", false},        // should not match partial of slashed ref
	}

	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			t.Parallel()
			got := GitRefExistsInRemote(lsRemoteOutput, tt.ref)
			if got != tt.want {
				t.Fatalf("GitRefExistsInRemote(output, %q) = %v, want %v", tt.ref, got, tt.want)
			}
		})
	}
}
