// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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

// This file tests the felix-specific validation rules implemented in the validation filter

package calc_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

type TestSyncer struct {
	Received []api.Update
}

func (t *TestSyncer) OnStatusUpdated(status api.SyncStatus) {
}

func (t *TestSyncer) OnUpdates(updates []api.Update) {
	t.Received = append(t.Received, updates...)
}

var _ = Describe("WorkloadEndpoint Source IP Spoofing validation", func() {
	var (
		vf   *calc.ValidationFilter
		conf *config.Config
		sink *TestSyncer
		// immutable test data
		workloadUpdateWithSpoofRequest = api.Update{
			KVPair: model.KVPair{
				Key: model.WorkloadEndpointKey{
					Hostname:       "localhostname",
					OrchestratorID: "k8s",
					WorkloadID:     "test-ns/test-pod",
					EndpointID:     "eth0",
				},
				Value: &model.WorkloadEndpoint{
					State:                      "active",
					Name:                       "cali1234",
					AllowSpoofedSourcePrefixes: []net.IPNet{mustParseNet("1.2.3.4/32")},
					Labels:                     map[string]string{"label": "value"},
					Mac:                        mustParseMac("01:02:03:04:05:06"),
					ProfileIDs:                 []string{},
					IPv4Nets:                   []net.IPNet{mustParseNet("10.0.0.1/32")},
					IPv6Nets:                   []net.IPNet{},
					Ports:                      []model.EndpointPort{},
				},
			},
		}
	)

	BeforeEach(func() {
		conf = config.New()
		sink = &TestSyncer{Received: make([]api.Update, 0)}
		vf = calc.NewValidationFilter(sink, conf)
	})

	It("shouldn't allow a workload with source IP spoofing by default", func() {
		vf.OnUpdates([]api.Update{workloadUpdateWithSpoofRequest})
		Expect(len(sink.Received)).To(Equal(1))
		Expect(sink.Received[0].Value).To(BeNil())
	})

	It("should allow a workload with an IP spoofing request if configured to do so", func() {
		conf.WorkloadSourceSpoofing = "Any"
		vf.OnUpdates([]api.Update{workloadUpdateWithSpoofRequest})
		Expect(len(sink.Received)).To(Equal(1))
		Expect(sink.Received).To(ConsistOf(workloadUpdateWithSpoofRequest))
	})
})
