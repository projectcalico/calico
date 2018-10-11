// Copyright (c) 2018 Tigera, Inc. All rights reserved.
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

package iptables_test

import (
	"testing"

	. "github.com/onsi/gomega"

	. "github.com/projectcalico/felix/iptables"
)

func TestFeatureDetection(t *testing.T) {
	RegisterTestingT(t)

	type test struct {
		iptablesVersion, kernelVersion string
		features                       Features
	}
	for _, tst := range []test{
		{
			"iptables v1.6.2",
			"Linux version 3.14.0",
			Features{
				RestoreSupportsLock: true,
				SNATFullyRandom:     true,
				MASQFullyRandom:     true,
			},
		},
		{
			"iptables v1.6.1",
			"Linux version 3.14.0",
			Features{
				RestoreSupportsLock: false,
				SNATFullyRandom:     true,
				MASQFullyRandom:     false,
			},
		},
		{
			"iptables v1.5.0",
			"Linux version 3.14.0",
			Features{
				RestoreSupportsLock: false,
				SNATFullyRandom:     false,
				MASQFullyRandom:     false,
			},
		},
		{
			"iptables v1.6.2",
			"Linux version 3.13.0",
			Features{
				RestoreSupportsLock: true,
				SNATFullyRandom:     false,
				MASQFullyRandom:     false,
			},
		},
		{
			"garbage",
			"Linux version 3.14.0",
			Features{
				RestoreSupportsLock: false,
				SNATFullyRandom:     false,
				MASQFullyRandom:     false,
			},
		},
		{
			"iptables v1.6.2",
			"garbage",
			Features{
				RestoreSupportsLock: true,
				SNATFullyRandom:     false,
				MASQFullyRandom:     false,
			},
		},
		{
			"error",
			"Linux version 3.14.0",
			Features{
				RestoreSupportsLock: false,
				SNATFullyRandom:     false,
				MASQFullyRandom:     false,
			},
		},
		{
			"iptables v1.6.2",
			"error",
			Features{
				RestoreSupportsLock: true,
				SNATFullyRandom:     false,
				MASQFullyRandom:     false,
			},
		},
	} {
		tst := tst
		t.Run("iptables version "+tst.iptablesVersion+" kernel "+tst.kernelVersion, func(t *testing.T) {
			RegisterTestingT(t)
			dataplane := newMockDataplane("filter", map[string][]string{})
			featureDetector := NewFeatureDetector()
			featureDetector.NewCmd = dataplane.newCmd
			featureDetector.ReadFile = dataplane.readFile

			if tst.iptablesVersion == "error" {
				dataplane.FailNextVersion = true
			} else {
				dataplane.Version = tst.iptablesVersion
			}

			if tst.kernelVersion == "error" {
				dataplane.FailNextReadFile = true
			} else {
				dataplane.KernelVersion = tst.kernelVersion
			}

			Expect(featureDetector.GetFeatures()).To(Equal(&tst.features))
		})
	}
}
