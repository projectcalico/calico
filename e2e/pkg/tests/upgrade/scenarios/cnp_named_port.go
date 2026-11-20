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

package scenarios

import (
	"context"
	"embed"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/projectcalico/calico/e2e/pkg/tests/upgrade"
)

//go:embed testdata/cnp-named-port
var cnpNamedPortFS embed.FS

var cnpGVR = schema.GroupVersionResource{Group: "policy.networking.k8s.io", Version: "v1beta1", Resource: "clusternetworkpolicies"}

// The v3.34 CNP CRD drops destinationNamedPort. A v1alpha2 rule using it must
// fail closed after the upgrade and must never fail open on the way, when
// pre-upgrade components can read the pruned {} entry as "all ports".
//
// Retire once no supported from-stream predates the v0.3.0 CRD.
func init() {
	upgrade.Register(upgrade.Scenario{
		Name:     "cnp-named-port",
		Feature:  "ClusterNetworkPolicy",
		From:     []string{"v3.32", "v3.33"},
		Fixtures: upgrade.Sub(cnpNamedPortFS, "testdata/cnp-named-port"),
		Probes: []upgrade.Probe{
			// No rule ever allows 9090, so any success is a fail-open window.
			{Name: "cli-9090", Client: "cli", Target: "svc:srv:9090", Protocol: "tcp", Expect: upgrade.AlwaysDenied},
			{Name: "cli-80", Client: "cli", Target: "svc:srv:80", Protocol: "tcp", Expect: upgrade.Expect{Before: upgrade.Allowed, After: upgrade.Denied}},
			{Name: "cli-8080", Client: "cli", Target: "svc:srv:8080", Protocol: "tcp", Expect: upgrade.Expect{Before: upgrade.Allowed, After: upgrade.Denied}},
			// Positive controls: srv was serving on every port throughout.
			{Name: "oth-80", Client: "oth", Target: "svc:srv:80", Protocol: "tcp", Expect: upgrade.AlwaysAllowed},
			{Name: "oth-8080", Client: "oth", Target: "svc:srv:8080", Protocol: "tcp", Expect: upgrade.AlwaysAllowed},
			{Name: "oth-9090", Client: "oth", Target: "svc:srv:9090", Protocol: "tcp", Expect: upgrade.AlwaysAllowed},
		},
		Verify: func(ctx context.Context, e *upgrade.Env) error {
			return upgrade.ExpectField(ctx, e, cnpGVR, "", "e2e-upgrade-cnp-named-port-accept", "{.spec.ingress[0].protocols[0]}", "{}")
		},
	})
}
