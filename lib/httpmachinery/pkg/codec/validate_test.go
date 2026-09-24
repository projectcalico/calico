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

type sortParams struct {
	SortBy string `urlQuery:"sortBy" validate:"omitempty,oneof=name age"`
	Name   string `urlQuery:"name" validate:"required"`
}

// The caller gets the field and the values it can take, not the validator's own
// vocabulary.
func TestURLParameterValidationErrorsAreTranslated(t *testing.T) {
	setupTest(t)

	req, err := http.NewRequest("GET", "http://example.com?name=foo&sortBy=height", nil)
	Expect(err).NotTo(HaveOccurred())
	_, err = codec.DecodeAndValidateRequestParams[sortParams](apicontext.NewRequestContext(req), NoopURLVarsFunc, req)
	Expect(err).To(HaveOccurred())
	Expect(err.Error()).To(Equal(`invalid sortBy "height", expected one of name, age`))

	req, err = http.NewRequest("GET", "http://example.com?sortBy=name", nil)
	Expect(err).NotTo(HaveOccurred())
	_, err = codec.DecodeAndValidateRequestParams[sortParams](apicontext.NewRequestContext(req), NoopURLVarsFunc, req)
	Expect(err).To(HaveOccurred())
	Expect(err.Error()).To(Equal("name is required"))
}
