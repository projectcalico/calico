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
	"fmt"
	"os"
	"sort"

	"gopkg.in/yaml.v3"
)

type Profile struct {
	Description        string `yaml:"description"`
	SemaphorePipeline  string `yaml:"semaphore_pipeline"`
	DefaultLabelFilter string `yaml:"default_label_filter"`
}

type profilesFile struct {
	Profiles map[string]Profile `yaml:"profiles"`
}

// loadProfiles reads the e2e-profiles.yaml file and returns the profile map.
func loadProfiles(path string) (map[string]Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading profiles: %w", err)
	}
	var pf profilesFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parsing profiles: %w", err)
	}
	if len(pf.Profiles) == 0 {
		return nil, fmt.Errorf("no profiles found in %s", path)
	}
	return pf.Profiles, nil
}

// validateProfile checks that the named profile exists and returns it.
func validateProfile(profiles map[string]Profile, name string) (Profile, error) {
	p, ok := profiles[name]
	if !ok {
		return Profile{}, fmt.Errorf("unknown profile %q; valid profiles: %s", name, profileNames(profiles))
	}
	return p, nil
}

// profileNames returns sorted profile names for display.
func profileNames(profiles map[string]Profile) string {
	names := make([]string, 0, len(profiles))
	for k := range profiles {
		names = append(names, k)
	}
	sort.Strings(names)
	result := ""
	for i, n := range names {
		if i > 0 {
			result += ", "
		}
		result += n
	}
	return result
}

// sortedProfileKeys returns profile names in sorted order for consistent display.
func sortedProfileKeys(profiles map[string]Profile) []string {
	keys := make([]string, 0, len(profiles))
	for k := range profiles {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
