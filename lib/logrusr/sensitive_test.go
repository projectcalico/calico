// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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

package logrusr

import (
	"strings"
	"testing"
)

func TestRedactURLCredentials(t *testing.T) {
	for _, raw := range []string{
		"https://test-user:test-password@example.com:8443/path?token=test-token#test-fragment",
		"https://test-user@example.com/path?token=test-token#test-fragment",
		"https://test-user:test-password@example.com/%zz",
		"test-user:test-password?token=test-token",
	} {
		got := RedactURL(raw)
		for _, secret := range []string{"test-user", "test-password", "test-token", "test-fragment"} {
			if strings.Contains(got, secret) {
				t.Fatalf("redacted URL contains credential")
			}
		}
	}
	if got := RedactURL("https://example.com:8443/path?token=test-token"); got != "https://example.com:8443/path" {
		t.Fatalf("unexpected redacted URL %q", got)
	}
}
