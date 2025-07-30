// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package images

import (
	"os"

	"k8s.io/kubernetes/test/e2e/framework"
)

const (
	Alpine        = "docker.io/alpine:3"
	Porter        = "calico/porter"
	TestWebserver = "gcr.io/kubernetes-e2e-test-images/test-webserver:1.0"
)

// Get client image and powershell command based on windows OS version
func WindowsClientImage() string {
	opsys := os.Getenv("WINDOWS_OS")
	if opsys == "" {
		framework.Failf("WINDOWS_OS env not specified. Please set env properly")
		return ""
	}
	if opsys == "1809" || opsys == "1909" || opsys == "1903" || opsys == "2004" || opsys == "20H2" {
		return "mcr.microsoft.com/windows/servercore:" + opsys
	} else if opsys == "2022" {
		// For 2022, servercore uses "ltsc2022" and does not have the image tag
		// "2022" (unlike previous Windows versions).
		return "mcr.microsoft.com/windows/servercore:ltsc2022"
	} else {
		framework.Failf("Windows OS version currently not supported: %s", opsys)
	}
	return ""
}
