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
	"strings"

	"github.com/onsi/ginkgo/v2"
)

// ClusterIsWindows returns true if the cluster supports running Windows tests and false otherwise.
//
// TODO: Right now, we assume that the presence of "RunsOnWindows" in the focus strings means
// that the tests are running on a Windows cluster. This isn't necessarily true. We could be more
// precise by either checking the cluster itself, or adding a CLi flag to control this behavior.
func ClusterIsWindows() bool {
	cfg, _ := ginkgo.GinkgoConfiguration()
	for _, s := range cfg.FocusStrings {
		if strings.Contains(s, "RunsOnWindows") {
			return true
		}
	}
	return false
}
