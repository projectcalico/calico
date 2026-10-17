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
	"regexp"
	"strings"
	"testing"
)

// escaped matches one byte of a binfmt_misc magic or mask: a \xNN escape or
// a literal character.
var escaped = regexp.MustCompile(`\\x[0-9a-f]{2}|[^\\]`)

// The kernel rejects a registration whose magic and mask differ in length, so
// a typo in either would only show up as a failed install on a CI runner.
func TestConfigMagicMatchesMask(t *testing.T) {
	for arch, cfg := range configs {
		magic := escaped.FindAllString(cfg.magic, -1)
		mask := escaped.FindAllString(cfg.mask, -1)
		if strings.Join(magic, "") != cfg.magic {
			t.Errorf("%s: magic %q has a malformed escape", arch, cfg.magic)
		}
		if strings.Join(mask, "") != cfg.mask {
			t.Errorf("%s: mask %q has a malformed escape", arch, cfg.mask)
		}
		if len(magic) != len(mask) {
			t.Errorf("%s: magic is %d bytes but mask is %d", arch, len(magic), len(mask))
		}
	}
}

func TestParseArch(t *testing.T) {
	got := parseArch("linux/arm64,s390x,riscv64")
	want := []string{"arm64", "s390x", "riscv64"}
	if len(got) != len(want) {
		t.Fatalf("parseArch = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parseArch = %v, want %v", got, want)
		}
	}
}
