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

package whiskerbackend

import (
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/apiutil"
	whiskerv1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
	"github.com/projectcalico/calico/whisker-backend/pkg/config"
	v1 "github.com/projectcalico/calico/whisker-backend/pkg/handlers/v1"
)

// newFlowsBackend wires the Goldmane flow backend — the only upstream in OSS
// builds, needing no endpoint middleware or flow handler options. Downstream
// forks replace this file with one wiring their own upstreams and middleware.
func newFlowsBackend(cfg *config.Config) (whiskerv1.FlowsBackend, []apiutil.Middleware, []v1.FlowsOption) {
	return newGoldmaneBackend(cfg), nil, nil
}
