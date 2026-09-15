// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

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

package operator

import "testing"

// A blank operator-registry flag must not leave the image published nowhere.
func TestBlankRegistryKeepsDefaults(t *testing.T) {
	o := NewManager(WithRegistry(""), WithValidate(false))
	if got := o.Registry(); got != DefaultRegistries[0] {
		t.Fatalf("Registry() = %q, want %q", got, DefaultRegistries[0])
	}
	if len(o.registries) != len(DefaultRegistries) {
		t.Fatalf("registries = %v, want %v", o.registries, DefaultRegistries)
	}
}

func TestRegistryIsFirstOfRegistries(t *testing.T) {
	o := NewManager(WithRegistries([]string{"a.io/x", "b.io/x"}), WithValidate(false))
	if got := o.Registry(); got != "a.io/x" {
		t.Fatalf("Registry() = %q, want a.io/x", got)
	}
}
