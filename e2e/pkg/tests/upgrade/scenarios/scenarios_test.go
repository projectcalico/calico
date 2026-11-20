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

package scenarios

import (
	"os"
	"regexp"
	"slices"
	"testing"

	"github.com/projectcalico/calico/e2e/pkg/tests/upgrade"
)

const upgradeCron = "../../../../../.argoci/cron/e2e-upgrade.yaml"

var (
	defaultStreamRE = regexp.MustCompile(`RELEASE_STREAM="\$\{RELEASE_STREAM:-(v[0-9]+\.[0-9]+)\}"`)
	cellStreamRE    = regexp.MustCompile(`(?m)- name: RELEASE_STREAM\s*\n\s*value: "?(v[0-9]+\.[0-9]+)"?`)
)

// cronStreams returns every from-stream the upgrade cron installs.
func cronStreams(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(upgradeCron)
	if err != nil {
		t.Fatalf("reading the upgrade cron: %v", err)
	}
	var streams []string
	if m := defaultStreamRE.FindSubmatch(data); m != nil {
		streams = append(streams, string(m[1]))
	}
	for _, m := range cellStreamRE.FindAllSubmatch(data, -1) {
		if s := string(m[1]); !slices.Contains(streams, s) {
			streams = append(streams, s)
		}
	}
	if len(streams) == 0 {
		t.Fatalf("found no RELEASE_STREAM in %s; has its format changed?", upgradeCron)
	}
	return streams
}

// A scenario whose from-streams the cron no longer installs is never
// selected. Delete it, or move From forward if it still applies.
func TestEveryScenarioRunsSomewhere(t *testing.T) {
	streams := cronStreams(t)
	scenarios := upgrade.Registered()
	if len(scenarios) == 0 {
		t.Fatal("no scenarios registered")
	}
	for _, s := range scenarios {
		if !slices.ContainsFunc(s.From, func(f string) bool { return slices.Contains(streams, f) }) {
			t.Errorf("scenario %s runs from %v, but the upgrade cron only installs %v", s.Name, s.From, streams)
		}
	}
}
