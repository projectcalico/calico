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

package apiconfig_test

import (
	"strings"
	"testing"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
)

// The API server records the text before the first slash as the field manager, so a
// component name that lands after one would leave every component sharing a manager.
func TestUserAgentForStartsWithTheComponentName(t *testing.T) {
	for _, component := range []string{
		"calico-node-startup",
		"calico-node-felix",
		"calico-node-confd",
		"calico-kube-controllers",
		"calico-typha",
		"calicoctl",
	} {
		agent := apiconfig.UserAgentFor(component)
		if manager := strings.Split(agent, "/")[0]; manager != component {
			t.Errorf("user agent %q gives field manager %q, want %q", agent, manager, component)
		}
	}
}

func TestUserAgentForNamesAnUnsetVersion(t *testing.T) {
	agent := apiconfig.UserAgentFor("calico-typha")
	if !strings.HasPrefix(agent, "calico-typha/unknown ") {
		t.Errorf("user agent %q should name the version, even when the build did not set one", agent)
	}
}
