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

package testconfig

import (
	"fmt"
	"regexp"
)

// Labels carried by the generated upgrade-scenario specs. base.yaml excludes
// the first two, so only ApplyUpgradePhase ever selects them.
const (
	UpgradeSeedLabel      = "Upgrade:Seed"
	UpgradeVerifyLabel    = "Upgrade:Verify"
	UpgradeFromLabelKey   = "UpgradeFrom"
	UpgradePhaseSeed      = "seed"
	UpgradePhaseVerify    = "verify"
	UpgradePhaseEnvVar    = "E2E_UPGRADE_PHASE"
	UpgradeFromEnvVar     = "E2E_UPGRADE_FROM"
	upgradeIncludeComment = "upgrade scenario phase selected by " + UpgradePhaseEnvVar
)

// Streams are ginkgo label values, so they must stay free of the filter
// language's operators.
var streamRE = regexp.MustCompile(`^(v[0-9]+\.[0-9]+|master)$`)

// UpgradeFromLabel is the label marking a scenario as runnable from stream.
func UpgradeFromLabel(stream string) string {
	return UpgradeFromLabelKey + ":" + stream
}

// ApplyUpgradePhase narrows or widens a lane's merged selection for one side
// of an upgrade. The YAML can't carry the from-stream itself because configs
// don't expand environment variables.
//
// seed replaces the lane's scope, since only seed specs may run on the old
// cluster, but keeps its excludes and provides, which describe the platform.
// verify adds the verify specs to the lane's normal post-upgrade scope.
func ApplyUpgradePhase(cfg *Config, phase, from string) error {
	if phase == "" {
		if from != "" {
			return fmt.Errorf("%s=%q is set without %s", UpgradeFromEnvVar, from, UpgradePhaseEnvVar)
		}
		return nil
	}
	if !streamRE.MatchString(from) {
		return fmt.Errorf("%s=%q: want a release stream such as v3.33", UpgradeFromEnvVar, from)
	}

	// Ginkgo ANDs focus with the label filter, so a phase include on a lane
	// that selects by name pattern would select nothing.
	if len(cfg.Include.NamePatterns) > 0 {
		return fmt.Errorf("%s=%s: the lane selects by name pattern, which would AND with the %s label filter", UpgradePhaseEnvVar, phase, phase)
	}

	var selected, stillExcluded string
	switch phase {
	case UpgradePhaseSeed:
		selected, stillExcluded = UpgradeSeedLabel, UpgradeVerifyLabel
		cfg.Include.Labels = nil
	case UpgradePhaseVerify:
		selected, stillExcluded = UpgradeVerifyLabel, UpgradeSeedLabel
	default:
		return fmt.Errorf("%s=%q: want %q or %q", UpgradePhaseEnvVar, phase, UpgradePhaseSeed, UpgradePhaseVerify)
	}

	if !excludesLabel(cfg, selected) || !excludesLabel(cfg, stillExcluded) {
		return fmt.Errorf("the lane's configs must exclude %s and %s (base.yaml does); otherwise normal runs select scenario specs", UpgradeSeedLabel, UpgradeVerifyLabel)
	}

	kept := cfg.Exclude.Labels[:0:0]
	for _, e := range cfg.Exclude.Labels {
		if e.Label != selected {
			kept = append(kept, e)
		}
	}
	cfg.Exclude.Labels = kept
	cfg.Include.Labels = append(cfg.Include.Labels, IncludeEntry{
		Label:  fmt.Sprintf("%s && %s", selected, UpgradeFromLabel(from)),
		Reason: upgradeIncludeComment,
	})
	return nil
}
