// Copyright (c) 2023 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fv_test

import (
	"fmt"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ Debug port tests", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	const nodeCount = 1

	var (
		infra           infrastructure.DatastoreInfra
		topologyOptions infrastructure.TopologyOptions
		tc              infrastructure.TopologyContainers
	)

	BeforeEach(func() {
		infra = getInfra()
		topologyOptions = infrastructure.DefaultTopologyOptions()
	})

	JustBeforeEach(func() {
		tc, _ = infrastructure.StartNNodeTopology(nodeCount, topologyOptions, infra)
	})

	get := func(path string) error {
		debugServer := fmt.Sprintf("http://%s:%d/", tc.Felixes[0].IP, 6061)
		httpClient := http.Client{
			Timeout: 2 * time.Second,
		}
		resp, err := httpClient.Get(debugServer + path)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != 200 {
			return fmt.Errorf("bad status code: %d", resp.StatusCode)
		}
		return nil
	}

	getFn := func(path string) func() error {
		return func() error {
			return get(path)
		}
	}

	Describe("with debug port enabled on 0.0.0.0", func() {
		BeforeEach(func() {
			topologyOptions.ExtraEnvVars["FELIX_DebugPort"] = "6061"
			topologyOptions.ExtraEnvVars["FELIX_DebugHost"] = "0.0.0.0"
		})

		It("should serve expected URLs", func() {
			Eventually(getFn("debug/pprof/profile?seconds=1")).ShouldNot(HaveOccurred())
			Expect(get("debug/pprof/heap")).NotTo(HaveOccurred())
			Expect(get("metrics")).To(HaveOccurred(), "Metrics on the debug port?")
		})
	})
})
