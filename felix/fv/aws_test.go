// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

//go:build fvtests

package fv_test

import (
	"fmt"
	"regexp"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
)

const (
	startLog  = "Setting AWS EC2 source-destination-check to Disable"
	failedLog = "Failed to set source-destination-check"
)

var _ = infrastructure.DatastoreDescribe("AWS-ec2-srcdstcheck", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra                                     infrastructure.DatastoreInfra
		felix                                     *infrastructure.Felix
		startEC2ContactLogC, failedEC2ContactLogC chan struct{}
	)

	BeforeEach(func() {
		infra = getInfra()
		opts := infrastructure.DefaultTopologyOptions()
		opts.ExtraEnvVars["FELIX_AWSSRCDSTCHECK"] = "Disable"
		opts.ExtraEnvVars["FELIX_HEALTHENABLED"] = "true"
		opts.ExtraEnvVars["FELIX_HEALTHHOST"] = "127.0.0.1"
		opts.DelayFelixStart = true
		felix, _ = infrastructure.StartSingleNodeTopology(opts, infra)
		// Install a default profile that allows all ingress and egress, in the absence of any Policy.
		infra.AddDefaultAllow()

		startEC2ContactLogC = felix.WatchStdoutFor(regexp.MustCompile(startLog))
		failedEC2ContactLogC = felix.WatchStdoutFor(regexp.MustCompile(failedLog))

		felix.TriggerDelayedStart()
	})

	AfterEach(func() {
		felix.Stop()
		if CurrentSpecReport().Failed() {
			infra.DumpErrorData()
		}
		infra.Stop()
	})

	getHTTPStatus := func(url string) (string, error) {
		op, err := felix.Container.ExecOutput("wget", "-S", "-T", "2", "-O", "-", "-o", "/dev/stdout", url)
		// Return output even when the error is set.
		// this is useful when wget sets err, in case of bad health status.
		return op, err
	}

	It("felix must be marked not-ready if source-destination-check setting fails", func() {
		// Without the correct credentials, AWS ec2 src-dst-check is bound to fail.
		// Make sure by looking at logs that the necessary logs messages exist.
		Eventually(startEC2ContactLogC, "10s", "100ms").Should(BeClosed())
		Eventually(failedEC2ContactLogC, "10s", "100ms").Should(BeClosed())

		// Felix is live...
		liveResponse, err := getHTTPStatus("http://127.0.0.1:9099/liveness")
		Expect(err).NotTo(HaveOccurred())
		Expect(liveResponse).To(ContainSubstring(fmt.Sprint(health.StatusGood)))
		// but not ready.
		readyResponse, err := getHTTPStatus("http://127.0.0.1:9099/readiness")
		Expect(err).To(HaveOccurred())
		Expect(readyResponse).To(ContainSubstring(fmt.Sprint(health.StatusBad)))
	})
})
