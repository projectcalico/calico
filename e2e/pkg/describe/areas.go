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

package describe

import (
	"k8s.io/kubernetes/test/e2e/framework"

	"github.com/projectcalico/calico/e2e/pkg/area"
)

// coversKey is the label key specs declare their feature area under.
const coversKey = "Covers"

// Covers marks a spec as exercising a feature area, for suite includes and for
// the per-area views on the CI dashboard. A value converted from a string
// outside area.All fails the spec tree, so a typo can't create an area nobody
// looks at.
func Covers(a area.Area) any {
	if !area.IsKnown(a) {
		framework.Failf("%s is not a supported area", a)
	}
	return framework.WithLabel(coversKey + ":" + string(a))
}
