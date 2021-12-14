// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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

package health

import (
	"context"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/app-policy/proto"
)

type reporter struct {
	Ready bool
}

func (r *reporter) Readiness() bool {
	return r.Ready
}

func TestHealthService(t *testing.T) {
	g := NewWithT(t)
	// Test happy path case where ReadinessReporter reports true.
	reporter := &reporter{
		Ready: true,
	}
	s := NewHealthCheckService(reporter)

	req := &proto.HealthCheckRequest{}
	resp, err := s.CheckReadiness(context.Background(), req)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(resp.Healthy).To(BeTrue())

	resp, err = s.CheckLiveness(context.Background(), req)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(resp.Healthy).To(BeTrue())

	// Now with ReadinessReporter returning false.
	reporter.Ready = false
	resp, err = s.CheckReadiness(context.Background(), req)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(resp.Healthy).To(BeFalse())

	resp, err = s.CheckLiveness(context.Background(), req)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(resp.Healthy).To(BeTrue())
}
