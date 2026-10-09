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
	"net/http"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/lib/httpmachinery/pkg/apiutil"
	v1mocks "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1/mocks"
	v1 "github.com/projectcalico/calico/whisker-backend/pkg/handlers/v1"
)

func TestWithMiddleware_AppliesToEveryEndpoint(t *testing.T) {
	RegisterTestingT(t)

	endpoints := v1.NewFlows(new(v1mocks.FlowsBackend)).APIs()
	Expect(endpoints).NotTo(BeEmpty())
	before := make([]int, len(endpoints))
	for i, ep := range endpoints {
		before[i] = len(ep.Middleware)
	}

	// Two markers stand in for authentication and cluster resolution; each
	// endpoint must gain both, after whatever it already declared.
	marker := apiutil.MiddlewareFunc(func(next http.Handler) http.Handler { return next })
	got := withMiddleware(endpoints, marker, marker)

	Expect(got).To(HaveLen(len(endpoints)))
	for i, ep := range got {
		Expect(ep.Middleware).To(HaveLen(before[i]+2), ep.Path)
	}
}
