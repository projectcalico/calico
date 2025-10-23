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

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/metrics"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ Prometheus metrics tests", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
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

	get := func(server, path string) error {
		httpClient := http.Client{
			Timeout: 2 * time.Second,
		}
		url := server + path
		resp, err := httpClient.Get(url)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != 200 {
			return fmt.Errorf("bad status code for %q: %d", url, resp.StatusCode)
		}
		return nil
	}

	Describe("with metrics and debug ports enabled", func() {
		BeforeEach(func() {
			topologyOptions.ExtraEnvVars["FELIX_PrometheusMetricsEnabled"] = "true"
			topologyOptions.ExtraEnvVars["FELIX_DebugPort"] = "6061"
			topologyOptions.ExtraEnvVars["FELIX_DebugHost"] = "0.0.0.0"
		})

		It("should serve a felix custom metric", func() {
			Eventually(tc.Felixes[0].PromMetric("felix_resync_state").Int).Should(Equal(3 /*in-sync*/))
		})

		It("should not serve debug paths on the prometheus port", func() {
			// Wait for server to come up.
			Eventually(tc.Felixes[0].PromMetric("felix_resync_state").Int).Should(Equal(3 /*in-sync*/))

			metricsServer := fmt.Sprintf("http://%s:%d/", tc.Felixes[0].IP, metrics.Port)
			debugServer := fmt.Sprintf("http://%s:%d/", tc.Felixes[0].IP, 6061)

			// Make sure we _can_ get the metrics manually...
			Expect(get(metricsServer, "metrics")).NotTo(HaveOccurred())
			debugPath := "debug/pprof/profile?seconds=1"
			// Make sure we _can_ get the debug paths on the debug server...
			Expect(get(debugServer, debugPath)).NotTo(HaveOccurred())
			Expect(get(metricsServer, debugPath)).To(HaveOccurred())
		})

		AfterEach(func() {
			tc.Stop()
			if CurrentGinkgoTestDescription().Failed {
				infra.DumpErrorData()
			}
			infra.Stop()
		})
	})
})
