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

package util

import (
	"fmt"
	"regexp"
	"strings"
)

// ShellQuote single-quotes s for a POSIX shell, so any value survives verbatim.
// Use it, never fmt %q, for anything going into a remote command: %q is
// double-quoted, and bash still expands $(...) inside double quotes.
//
// The escape itself is only in the code below -- gofmt rewrites a doubled
// apostrophe in a doc comment into a curly quote.
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// shellName is the portable environment-variable name: a leading letter or
// underscore, then letters, digits or underscores.
var shellName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// CheckShellName rejects a name that cannot be used as a shell variable. Values
// can be quoted, but a NAME is interpolated bare into `export NAME=...`, so
// something like "FOO; rm -rf /" would run when the file is sourced.
func CheckShellName(name string) error {
	if !shellName.MatchString(name) {
		return fmt.Errorf("%q is not a valid environment variable name", name)
	}
	return nil
}
