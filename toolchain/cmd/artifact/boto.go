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

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// botoServiceKeyFile returns the gs_service_key_file set in the [Credentials]
// section of the boto config at path, or "" when there is none. Like boto, it
// treats a config file that cannot be read as absent.
func botoServiceKeyFile(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	if rest, ok := strings.CutPrefix(path, "~"); ok && (rest == "" || rest[0] == '/') {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, rest)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil
	}
	v, err := iniValue(bytes.NewReader(data), "Credentials", "gs_service_key_file")
	if err != nil {
		return "", fmt.Errorf("BOTO_CONFIG %s: %w", path, err)
	}
	return v, nil
}

// iniValue reads the file the way Python's configparser does, since that is
// what boto uses: section names are case-sensitive, option names are not,
// '=' or ':' separates, and only whole-line '#' or ';' comments are removed.
// A more indented line continues the previous value.
func iniValue(r io.Reader, section, option string) (string, error) {
	var (
		cur        string
		anySection bool
		inSection  bool
		found      bool
		value      string
		inOption   bool
		indent     int
	)
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimRight(sc.Text(), " \t\r")
		trimmed := strings.TrimLeft(line, " \t")
		lineIndent := len(line) - len(trimmed)
		if trimmed == "" || trimmed[0] == '#' || trimmed[0] == ';' {
			continue
		}
		if inOption && lineIndent > indent {
			if inSection && found && strings.EqualFold(cur, option) {
				value += "\n" + trimmed
			}
			continue
		}
		inOption = false
		if trimmed[0] == '[' && strings.HasSuffix(trimmed, "]") && len(trimmed) > 2 {
			anySection = true
			inSection = trimmed[1:len(trimmed)-1] == section
			continue
		}
		i := strings.IndexAny(trimmed, "=:")
		if i < 0 {
			return "", fmt.Errorf("line %d: expected 'option = value'", n)
		}
		if !anySection {
			return "", fmt.Errorf("line %d: option before any [section]", n)
		}
		cur = strings.TrimSpace(trimmed[:i])
		inOption, indent = true, lineIndent
		if inSection && strings.EqualFold(cur, option) {
			found, value = true, strings.TrimSpace(trimmed[i+1:])
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return value, nil
}
