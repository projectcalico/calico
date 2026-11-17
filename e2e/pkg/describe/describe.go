// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package describe

import (
	"fmt"
	"strings"

	"github.com/onsi/ginkgo/v2"
	"k8s.io/kubernetes/test/e2e/framework"
)

// CalicoDescribe is a SIGDescribe for the Calico e2e tests.
var CalicoDescribe = framework.SIGDescribe("calico")

type Team string

const (
	Core Team = "CORE"
)

// WithTeam labels a spec with the team that owns it.
func WithTeam(team Team) any {
	return framework.WithLabel(fmt.Sprintf("Team:%s", team))
}

// features is the set of high level features that are tested by the e2e tests.
// Every suite must cover at least one of these.
//
// If you are unsure which feature to use, please ask!
var features = map[string]bool{
	"NetworkPolicy":   true,
	"Tiered-Policy":   true,
	"IPPool":          true,
	"IPAM":            true,
	"AutoHEPs":        true,
	"Host-Protection": true,
	"HostPorts":       true,
	"OwnerReferences": true,
	"MTU":             true,
	"Maglev":          true,
	"BGPPeer":         true,
	"IPIP":            true,
	"Tiered-RBAC":     true,
	"Pods":            true,
	"QoS":             true,
	"Datapath":        true,
	"IngressGateway":  true,
	"Istio":           true,
	"KubeVirt":        true,
	"Wireguard":       true,
	"Flow-Logs":       true,
	"Windows":         true,
}

// Import of framework functions to keep imports in test files simpler.
var (
	WithSerial     = framework.WithSerial
	WithDisruptive = framework.WithDisruptive
)

// IncludesFocus returns true if the focus string used to run the tests includes the given substring.
// This is useful to allow tests to modify their behavior based on whether or not they are being focused. For example,
// tests should not self-skip if they are actively focused.
func IncludesFocus(s string) bool {
	suiteConfig, _ := ginkgo.GinkgoConfiguration()
	for _, focus := range suiteConfig.FocusStrings {
		if strings.Contains(focus, s) {
			return true
		}
	}
	return false
}
