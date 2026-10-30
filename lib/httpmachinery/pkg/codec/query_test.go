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

package codec_test

import (
	"net/http"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/lib/httpmachinery/pkg/codec"
	apicontext "github.com/projectcalico/calico/lib/httpmachinery/pkg/context"
)

type pageParams struct {
	Page int `urlQuery:"page"`
}

type listParams struct {
	pageParams `urlQuery:",inline"`
	Search     string `urlQuery:"search"`
	Name       string `urlPath:"name"`
	Cluster    string `header:"X-Cluster-Id"`
}

func TestQueryParamNames(t *testing.T) {
	setupTest(t)

	names := codec.QueryParamNames[listParams]()
	Expect(names).To(HaveLen(2))
	Expect(names).To(HaveKey("page"))
	Expect(names).To(HaveKey("search"))

	// A type with no urlQuery field at all still answers, so a route that takes
	// none rejects every parameter rather than accepting any.
	type pathOnly struct {
		Name string `urlPath:"name"`
	}
	Expect(codec.QueryParamNames[pathOnly]()).To(BeEmpty())
}

// A parameter the params type does not declare is a 400. Decoding ignores it,
// so a misspelt filter would otherwise answer 200 with the filter not applied.
func TestUnknownQueryParameterIsRejected(t *testing.T) {
	setupTest(t)

	req, err := http.NewRequest("GET", "http://example.com?search=foo&serach=bar", nil)
	Expect(err).NotTo(HaveOccurred())
	_, err = codec.DecodeAndValidateRequestParams[listParams](apicontext.NewRequestContext(req), NoopURLVarsFunc, req)
	Expect(err).To(HaveOccurred())
	Expect(err.Error()).To(ContainSubstring(`unknown query parameter "serach"`))

	req, err = http.NewRequest("GET", "http://example.com?search=foo&page=2", nil)
	Expect(err).NotTo(HaveOccurred())
	param, err := codec.DecodeAndValidateRequestParams[listParams](apicontext.NewRequestContext(req), NoopURLVarsFunc, req)
	Expect(err).NotTo(HaveOccurred())
	Expect(param.Search).To(Equal("foo"))
	Expect(param.Page).To(Equal(2))
}
