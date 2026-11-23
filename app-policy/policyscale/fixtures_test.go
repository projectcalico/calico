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

package policyscale

import "sync"

// The measured presets take seconds to build under the race detector, and a built fixture doesn't
// change, so tests that only read one share a single build.
var (
	compositeFixture = sync.OnceValue(func() *Fixture { return Build(Composite()) })
	baselineFixture  = sync.OnceValue(func() *Fixture { return Build(Baseline()) })
	egressFixture    = sync.OnceValue(func() *Fixture { return Build(EgressAllowList()) })
)

// CompositeFixture, BaselineFixture and EgressFixture give the package's external tests the shared
// builds.
func CompositeFixture() *Fixture { return compositeFixture() }
func BaselineFixture() *Fixture  { return baselineFixture() }
func EgressFixture() *Fixture    { return egressFixture() }
