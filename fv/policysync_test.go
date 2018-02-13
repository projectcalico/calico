// +build fvtests

// Copyright (c) 2018 Tigera, Inc. All rights reserved.
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

package fv

import (
	"context"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/colabsaumoh/proto-udsuspver/nodeagentmgmt"
	"github.com/colabsaumoh/proto-udsuspver/protos/mgmtintf_v1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/projectcalico/felix/proto"

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/felix/fv/utils"
	"github.com/projectcalico/felix/fv/workload"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
)

var _ = Context("policy sync API tests", func() {

	var (
		etcd    *containers.Container
		felix   *containers.Felix
		client  client.Interface
		w       [3]*workload.Workload
		tempDir string
	)

	BeforeEach(func() {
		var err error
		tempDir, err = ioutil.TempDir("", "felixfv")
		Expect(err).NotTo(HaveOccurred())

		options := containers.DefaultTopologyOptions()
		options.ExtraEnvVars["FELIX_PolicySyncManagementSocketPath"] = "/var/run/calico/policy-mgmt.sock"
		options.ExtraEnvVars["FELIX_PolicySyncWorkloadSocketPathPrefix"] = "/var/run/calico"
		options.ExtraVolumes[tempDir] = "/var/run/calico"
		felix, etcd, client = containers.StartSingleNodeEtcdTopology(options)

		// Install a default profile that allows workloads with this profile to talk to each
		// other, in the absence of any Policy.
		defaultProfile := api.NewProfile()
		defaultProfile.Name = "default"
		defaultProfile.Spec.LabelsToApply = map[string]string{"default": ""}
		defaultProfile.Spec.Egress = []api.Rule{{Action: api.Allow}}
		defaultProfile.Spec.Ingress = []api.Rule{{
			Action: api.Allow,
			Source: api.EntityRule{Selector: "default == ''"},
		}}
		_, err = client.Profiles().Create(utils.Ctx, defaultProfile, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// Create three workloads, using that profile.
		for ii := range w {
			iiStr := strconv.Itoa(ii)
			w[ii] = workload.Run(felix, "w"+iiStr, "cali1"+iiStr, "10.65.0.1"+iiStr, "8055", "tcp")
			w[ii].WorkloadEndpoint.Spec.Endpoint = "eth0"
			w[ii].WorkloadEndpoint.Spec.Orchestrator = "k8s"
			w[ii].WorkloadEndpoint.Spec.Pod = "fv-pod-" + iiStr
			w[ii].Configure(client)
		}
	})

	AfterEach(func() {
		for ii := range w {
			w[ii].Stop()
		}
		felix.Stop()

		if CurrentGinkgoTestDescription().Failed {
			etcd.Exec("etcdctl", "ls", "--recursive", "/")
		}
		etcd.Stop()
	})

	AfterEach(func() {
		if tempDir != "" {
			err := os.RemoveAll(tempDir)
			Expect(err).NotTo(HaveOccurred(), "Failed to clean up temp dir")
		}
	})

	It("should do policy sync", func() {
		By("Creating the management socket")
		hostMgmtSocketPath := tempDir + "/policy-mgmt.sock"
		Eventually(hostMgmtSocketPath).Should(BeAnExistingFile())

		// Use the fact that anything we exec inside the Felix container runs as root to fix the
		// permissions on the socket so the test process can connect.
		felix.Exec("chmod", "a+rw", "/var/run/calico/policy-mgmt.sock")

		By("Accepting a connection from the management API client")
		client := nodeagentmgmt.ClientUds(hostMgmtSocketPath)
		// Create the workload directory, this would normally be the responsibility of the
		// flex volume driver.
		hostWlDir := tempDir + "/wl0"
		os.MkdirAll(hostWlDir, 0777)
		Eventually(func() error {
			resp, err := client.WorkloadAdded(&mgmtintf_v1.WorkloadInfo{
				Attrs: &mgmtintf_v1.WorkloadInfo_WorkloadAttributes{
					Uid:       "fv-pod-0",
					Namespace: "fv",
					Workload:  "fv-pod-0",
				},
				Workloadpath: "wl0",
			})
			log.WithField("response", resp).Info("WorkloadAdded response")
			return err
		}).ShouldNot(HaveOccurred())

		By("Creating the per-workload socket")
		hostWlSocketPath := hostWlDir + "/policysync.sock"
		Eventually(hostWlSocketPath).Should(BeAnExistingFile())

		By("Accepting connections on the per-workload socket")

		// Use the fact that anything we exec inside the Felix container runs as root to fix the
		// permissions on the socket so the test process can connect.
		felix.Exec("chmod", "a+rw", "/var/run/calico/wl0/policysync.sock")

		// Then connect to it.
		var conn *grpc.ClientConn
		var err error
		var opts []grpc.DialOption

		opts = append(opts, grpc.WithInsecure())
		opts = append(opts, grpc.WithDialer(unixDialer))
		conn, err = grpc.Dial(hostWlSocketPath, opts...)
		Expect(err).NotTo(HaveOccurred())

		c := proto.NewPolicySyncClient(conn)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		syncClient, err := c.Sync(ctx, &proto.SyncRequest{})
		Expect(err).NotTo(HaveOccurred())
		msg, err := syncClient.Recv()
		Expect(err).NotTo(HaveOccurred())
		log.WithField("message", msg).Info("Received message")
	})
})

func unixDialer(target string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", target, timeout)
}
