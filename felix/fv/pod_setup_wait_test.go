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
	"path/filepath"
	"regexp"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ Pod setup status wait", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	const nodeCount = 1

	var (
		infra                    infrastructure.DatastoreInfra
		topologyOptions          infrastructure.TopologyOptions
		tc                       infrastructure.TopologyContainers
		dummyWorkloads           [2]*workload.Workload
		dataplaneInSyncReceivedC chan struct{}
	)

	BeforeEach(func() {
		infra = getInfra()
		topologyOptions = infrastructure.DefaultTopologyOptions()
		topologyOptions.DelayFelixStart = true
		topologyOptions.EnableIPv6 = false
		// /tmp should be automatically mounted by an internal call to RunFelix
		// by the infrastructure pkg when Topology is started.
		topologyOptions.ExtraEnvVars["FELIX_ENDPOINTSTATUSPATHPREFIX"] = "/tmp"
		topologyOptions.ExtraEnvVars["FELIX_DEBUGDISABLElOGDROPPING"] = "true"
		topologyOptions.FelixLogSeverity = "Debug"
		topologyOptions.FelixDebugFilenameRegex = "status_file_reporter"

		tc, _ = infrastructure.StartNNodeTopology(nodeCount, topologyOptions, infra)
		tc.Felixes[0].Exec("rm", "-rf", "/tmp/endpoint-status")
		dataplaneInSyncReceivedC = tc.Felixes[0].WatchStdoutFor(regexp.MustCompile("DataplaneInSync received from upstream"))
	})

	AfterEach(func() {
		tc.Stop()
		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}
		infra.Stop()
	})

	Describe("with the file-reporter writing endpoint status to '/tmp/endpoint-status'", func() {
		buildStatCmdInFelix := func(felix *infrastructure.Felix, filename string) func() error {
			return func() error {
				return felix.ExecMayFail("stat", filename)
			}
		}

		It("should receive DataplaneInSync message from the dataplane", func() {
			tc.Felixes[0].TriggerDelayedStart()
			Eventually(dataplaneInSyncReceivedC, "10s").Should(BeClosed(), "receipt of DataplaneInSync message not seen in logs")
		})

		It("should create endpoint-status files in a directory named endpoint-status with the specified directory prefix", func() {
			tc.Felixes[0].TriggerDelayedStart()
			var filenames [2]string
			var statCmds [2]func() error
			for i := range dummyWorkloads {
				dummyWorkloads[i] = workload.New(tc.Felixes[0], fmt.Sprintf("workload-endpoint-status-tests-%d", i), "default", fmt.Sprintf("10.65.0.%d", 10+i), "8080", "tcp")
				err := dummyWorkloads[i].Start()
				Expect(err).NotTo(HaveOccurred())
				dummyWorkloads[i].ConfigureInInfra(infra)

				key, err := names.V3WorkloadEndpointToWorkloadEndpointKey(dummyWorkloads[i].WorkloadEndpoint)
				Expect(err).NotTo(HaveOccurred())
				filenames[i] = names.WorkloadEndpointKeyToStatusFilename(key)
				statCmds[i] = buildStatCmdInFelix(tc.Felixes[0], filepath.Join("/tmp/endpoint-status", filenames[i]))
			}

			Expect(filenames[0]).NotTo(Equal(filenames[1]), "duplicated filenames found")

			for i := range dummyWorkloads {
				Eventually(statCmds[i], "10s").Should(BeNil(), "status file was not programmed")
			}

			for i, w := range dummyWorkloads {
				w.RemoveFromInfra(infra)
				Eventually(statCmds[i], "10s").Should(HaveOccurred(), "status file was not deleted following workload removal")
			}
		})

		It("should cleanup stale files after a restart", func() {
			By("creating a file whose name we know Felix will not match to a workload")
			name := filepath.Join("/tmp/endpoint-status", "sdfsdf")
			tc.Felixes[0].Exec("mkdir", "/tmp/endpoint-status")
			tc.Felixes[0].Exec("touch", name)

			By("Waiting for Felix's status file reporter to come in-sync")
			tc.Felixes[0].TriggerDelayedStart()
			Eventually(dataplaneInSyncReceivedC, "10s").Should(BeClosed(), "receipt of DataplaneInSync message not seen in logs")

			By("checking if the stale file has been cleaned up")
			fileExists := func() bool {
				logrus.WithField("file", name).Info("Checking existence of expected file in endpoint-status dir")
				_, err := tc.Felixes[0].ExecOutput("stat", name)
				return err == nil
			}
			Eventually(fileExists).Should(BeFalse(), "Stale file was not cleaned up by Felix")
		})

		It("should re-use pre-existing, valid files after a restart", func() {
			By("creating a workload before Felix starts")
			wl := workload.New(tc.Felixes[0], "workload-endpoint-status-tests-0", "default", "10.65.0.10", "8080", "tcp")
			wl.ConfigureInInfra(infra)
			err := wl.Start()
			Expect(err).NotTo(HaveOccurred(), "Couldn't start a test workload")

			By("determining the filename Felix will look for")
			wKey, err := names.V3WorkloadEndpointToWorkloadEndpointKey(wl.WorkloadEndpoint)
			Expect(err).NotTo(HaveOccurred())
			Expect(wKey).NotTo(BeNil(), "failed to create a workload endpoint key from a v3 workload endpoint")

			filename := names.WorkloadEndpointKeyToStatusFilename(wKey)
			Expect(filename).NotTo(HaveLen(0), "failed to create a status filename from a workload endpoint key")

			By("creating a file with the determined name before Felix starts")
			expectedFilename := filepath.Join("/tmp/endpoint-status", filename)
			tc.Felixes[0].Exec("mkdir", "/tmp/endpoint-status")
			tc.Felixes[0].Exec("touch", expectedFilename)
			// This stat call returns the time since epoch when the file was last accessed.
			lastAccessed, err := tc.Felixes[0].ExecOutput("stat", "--format='%y'", expectedFilename)
			Expect(err).NotTo(HaveOccurred(), "stat call failed while trying to create a file")

			By("waiting for Felix's status file reporter to become in-sync")
			tc.Felixes[0].TriggerDelayedStart()
			Eventually(dataplaneInSyncReceivedC, "10s").Should(BeClosed(), "receipt of DataplaneInSync message not seen in logs")

			By("checking if the pre-existing file's access time changed")
			checkLastAccessed := func() string {
				lastAccessedPostStartup, _ := tc.Felixes[0].ExecOutput("stat", "--format='%y'", expectedFilename)
				return lastAccessedPostStartup
			}
			Consistently(checkLastAccessed, "3s").Should(BeEquivalentTo(lastAccessed), "felix modified/deleted a file it didn't need to, or the test and Felix expected differing filenames")
		})
	})

})
