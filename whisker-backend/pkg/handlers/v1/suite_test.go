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

package v1_test

import (
	"testing"
	"time"

	. "github.com/onsi/gomega"

	apicontextmocks "github.com/projectcalico/calico/lib/httpmachinery/pkg/context/mocks"
	"github.com/projectcalico/calico/lib/std/log"
)

type scaffold struct {
	apiCtx   *apicontextmocks.Context
	zeroTime time.Time
}

func setupTest(t *testing.T) scaffold {
	RegisterTestingT(t)

	ctx := new(apicontextmocks.Context)
	ctx.On("Logger").Return(log.NewEntry(log.StandardLogger()), "")

	zeroTime, err := time.Parse(time.RFC3339, "1970-01-01T00:00:00Z")
	Expect(err).ShouldNot(HaveOccurred())

	return scaffold{
		apiCtx:   ctx,
		zeroTime: zeroTime,
	}
}
