// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

// TODO: We shouldn't need a Team label - we can maintain a mapping of feature / category -> team.
func WithTeam(team Team) any {
	return framework.WithLabel(fmt.Sprintf("Team:%s", team))
}

// TODO: These categories are largely inherited from organically grown feature categories.
//
//	Is this really the right breakdown?
type Category string

const (
	// Policy is used for tests that verify policy enforcement behavior in the dataplane.
	Policy        Category = "Policy"
	Configuration Category = "Configuration"
	Operator      Category = "Operator"
	Networking    Category = "Networking"
)

func WithCategory(cat Category) any {
	return framework.WithLabel(fmt.Sprintf("Category:%s", cat))
}

// features is the set of high level features that are tested by the e2e tests.
// All tests must be marked with one of these features.
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
}

// RequiresNoEncap marks tests that require unencapsulated traffic to function.
// This is typically used for tests that verify BGP functionality without IPIP, or other similar tests.
// Such tests must be run on clusters that support unencapsulated traffic, such as bare-metal clusters
// or cloud clusters with appropriate configuration.
func RequiresNoEncap() any {
	return framework.WithLabel("NoEncap")
}

// WithFeature marks tests as verifying a specific feature.
func WithFeature(feature string) any {
	if !features[feature] {
		framework.Failf("%s is not a supported feature", feature)
	}
	return framework.WithLabel(fmt.Sprintf("Feature:%s", feature))
}

// WithWindows marks tests that can run on clusters with Windows nodes.
func WithWindows() any {
	return framework.WithLabel("RunsOnWindows")
}

// WithAzure marks tests that must run on Azure.
func WithAzure() any {
	return framework.WithLabel("RunsOnAzure")
}

// WithAWS marks tests that must run on AWS.
func WithAWS() any {
	return framework.WithLabel("RunsOnAWS")
}

// WithExternalNode marks tests that require an external node outside of the base cluster,
// and additional configuration passed to the e2e code in order to run commands on that node.
func WithExternalNode() any {
	return framework.WithLabel("ExternalNode")
}

// RequiresAzureIPAM marks tests that require a cluster with Azure IPAM.
func RequiresAzureIPAM() any {
	return framework.WithLabel("AzureIPAM")
}

// RequiresRKE2 marks tests that require an RKE2 environment.
func RequiresRKE2() any {
	return framework.WithLabel("RunsOnRKE2")
}

// RequiresRKE marks tests that require RHEL nodes.
func RequiresRHEL() any {
	return framework.WithLabel("RunsOnRHEL")
}

// WithSmokeTest marks tests that are considered smoke tests.
// A Smoke test must pass in under a minute, and is expected to pass on all platforms regardless of configuration.
func WithSmokeTest() any {
	return framework.WithLabel("SmokeTest")
}

// Dataplane defines a dataplane requirement.
type Dataplane string

const (
	BPF Dataplane = "BPF"
	LB  Dataplane = "LB"
)

func WithDataplane(d Dataplane) any {
	return framework.WithLabel(fmt.Sprintf("Dataplane:%s", d))
}

// WithObserve marks tests that may be obsolete or insuitable for e2e testing.
// These are tests that either are duplicated by another e2e test, are suitably covered via UTs / FVs, or
// just generally don't apply to the current state of the codebase.
func WithObserve() any {
	return framework.WithLabel("Observe")
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
