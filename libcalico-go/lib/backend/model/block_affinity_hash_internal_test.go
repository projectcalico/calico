// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

// Package model to access unexported hashHostnameForLabel for a golden test.
package model

import "testing"

// TestHashHostnameForLabelGolden verifies the exact hash output for a stable input.
// This protects against accidental changes to the hash algorithm or encoding.
func TestHashHostnameForLabelGolden(t *testing.T) {
	got := hashHostnameForLabel("node-a")
	want := "PY3TQE2E3XMTETLM2MJO3UITKPFB27YUJ4T4E5XGPEJON3SM4QAA"
	if got != want {
		t.Fatalf("hashHostnameForLabel(\"node-a\") = %q, want %q", got, want)
	}
}
