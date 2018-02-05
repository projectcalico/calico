// Copyright (c) 2018 Tigera, Inc. All rights reserved.

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

package checker

import (
	"context"
	"testing"

	. "github.com/onsi/gomega"

	authz "github.com/envoyproxy/data-plane-api/api/auth"
	"github.com/projectcalico/app-policy/policystore"
)

func TestCheck(t *testing.T) {
	RegisterTestingT(t)

	store := policystore.NewPolicyStore()
	uut := NewServer(store)

	ctx := context.Background()
	req := &authz.CheckRequest{}
	resp, err := uut.Check(ctx, req)
	Expect(err).To(BeNil())
	Expect(resp.GetStatus().GetCode()).To(Equal(PERMISSION_DENIED))
}
