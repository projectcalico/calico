// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

// Package operatorimages checks the images this repo builds against the ones the operator deploys.
package operatorimages

import (
	"fmt"
	"slices"
	"strings"

	"github.com/projectcalico/calico/operator/pkg/components"
)

// notDeployed maps an image this repo publishes to the reason the operator does not deploy it.
var notDeployed = map[string]string{}

// Check fails when an image this repo builds is absent from the operator's component list. The
// reverse is not checked: the operator also names images built outside this repo.
func Check(built []string) error {
	undeployed := missing(built, deployed())
	if len(undeployed) == 0 {
		return nil
	}
	return fmt.Errorf("the operator does not deploy images built here: %s; add each to a component list in operator/pkg/components, or to notDeployed with its reason",
		strings.Join(undeployed, ", "))
}

// deployed returns the image names the operator's component list carries, plus the operator's
// own image, which the list leaves out because the operator does not deploy itself.
func deployed() []string {
	comps := append(slices.Clone(components.CalicoImages), components.ComponentOperatorInit)
	out := make([]string, 0, len(comps))
	for _, c := range comps {
		out = append(out, c.Image)
	}
	return out
}

// missing returns the built images no component names, less the exceptions.
func missing(built, deployed []string) []string {
	var out []string
	for _, img := range built {
		if _, ok := notDeployed[img]; ok {
			continue
		}
		if slices.Contains(deployed, img) || slices.Contains(out, img) {
			continue
		}
		out = append(out, img)
	}
	slices.Sort(out)
	return out
}
