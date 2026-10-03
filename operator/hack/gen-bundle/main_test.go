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

package main

import "testing"

// TestSemverFlag covers the version flags, whose values name the directory that
// update-bundle clears - so anything that could escape it has to be refused.
func TestSemverFlag(t *testing.T) {
	t.Parallel()

	validate := semverFlag("version")
	for _, value := range []string{"3.34.0", "0.0.0", "3.34.0-1.0"} {
		if err := validate(value); err != nil {
			t.Errorf("%q was rejected: %v", value, err)
		}
	}
	for _, value := range []string{"", "v3.34.0", "3.34", "../../tmp", "3.34.0/../..", "3.34.0 "} {
		if err := validate(value); err == nil {
			t.Errorf("%q was accepted, want an error", value)
		}
	}
}
