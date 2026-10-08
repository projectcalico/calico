/*
Copyright (c) 2018 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// This package makes public methods out of some of the utility methods for testing windows cluster found at test/e2e/network_policy.go
// Eventually these utilities should replace those and be used for any calico tests

package windows

import (
	"slices"
	"strings"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/ginkgo/v2/types"
)

const windowsLabel = "RunsOnWindows"

// ClusterIsWindows returns true if the cluster supports running Windows tests and false otherwise.
//
// TODO: Right now, we infer this from the run selecting specs by "RunsOnWindows". This isn't
// necessarily true. We could be more precise by either checking the cluster itself, or adding a
// CLI flag to control this behavior.
func ClusterIsWindows() bool {
	cfg, _ := ginkgo.GinkgoConfiguration()
	return selectsWindows(cfg.FocusStrings, cfg.LabelFilter, ginkgo.CurrentSpecReport().Labels())
}

// selectsWindows reports whether the run selects specs by the Windows label, either via a focus
// string or via a label filter that would reject the current spec without it. Evaluating the
// filter, rather than searching it for the label, keeps a negated "!RunsOnWindows" from counting.
func selectsWindows(focusStrings []string, labelFilter string, specLabels []string) bool {
	for _, s := range focusStrings {
		if strings.Contains(s, windowsLabel) {
			return true
		}
	}
	if labelFilter == "" || !slices.Contains(specLabels, windowsLabel) {
		return false
	}
	filter, err := types.ParseLabelFilter(labelFilter)
	if err != nil {
		return false
	}
	without := slices.DeleteFunc(slices.Clone(specLabels), func(l string) bool { return l == windowsLabel })
	return !filter(without)
}
