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

package logutils

import (
	"net/url"
	"strings"
)

// sensitiveSubstrings are substrings that, when found in a lowercased
// config parameter name, indicate the value may contain credentials.
var sensitiveSubstrings = []string{
	"password", "passwd", "passphrase",
	"token", "bearer",
	"secret",
	"credential",
	"authorization",
	"cookie",
	"private",
}

// sensitiveSuffixes are suffixes that indicate inline key/cert material
// (as opposed to file paths like "keyfile" or "certpath").
var sensitiveSuffixes = []string{"key", "cert", "kubeconfig", "kubeconfiginline"}

// IsSensitiveParam reports whether a configuration parameter name suggests
// its value may contain credentials or key material.  Parameters whose names
// end in "file" or "path" are assumed to be file-system paths (not inline
// secrets) and are excluded.
func IsSensitiveParam(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasSuffix(lower, "file") || strings.HasSuffix(lower, "path") {
		return false
	}
	for _, sub := range sensitiveSubstrings {
		if strings.Contains(lower, sub) {
			return true
		}
	}
	for _, suffix := range sensitiveSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

// RedactURL parses a URL string and returns its Redacted() form, which masks
// any userinfo password while preserving the scheme, host, port, and path.
// If the URL cannot be parsed, it returns "<invalid-url>".
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<invalid-url>"
	}
	return u.Redacted()
}
