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

var _ = FContext("with initialized Felix, etcd datastore, 3 workloads", func() {

	var (
		etcd   *containers.Container
		felix  *containers.Container
		client client.Interface
		w      [3]*workload.Workload
	)

	BeforeEach(func() {
		// TODO: Unique directory for each run!
		os.Remove("/tmp/fvtest-calico-run/policysync.sock")
		felix, etcd, client = containers.StartSingleNodeEtcdTopology()

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
		_, err := client.Profiles().Create(utils.Ctx, defaultProfile, utils.NoOptions)
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

	It("should do policy sync", func() {
		By("Creating the socket")
		Eventually(func() error {
			_, err := os.Stat("/tmp/fvtest-calico-run/policysync.sock")
			return err
		}).ShouldNot(HaveOccurred())
		// TODO Permissions on sockets
		felix.Exec("chmod", "a+rw", "/var/run/calico/policysync.sock")
		felix.Exec("rm", "-rf", "/var/run/calico/wl0")
		felix.Exec("mkdir", "-p", "/var/run/calico/wl0")

		By("Accepting a connection from the management API client")
		client := nodeagentmgmt.ClientUds("/tmp/fvtest-calico-run/policysync.sock")
		Eventually(func() error {
			resp, err := client.WorkloadAdded(&mgmtintf_v1.WorkloadInfo{
				Attrs: &mgmtintf_v1.WorkloadInfo_WorkloadAttributes{
					Uid:       "fv-pod-0",
					Namespace: "fv",
					Workload:  "fv-pod-0",
				},
				Workloadpath: "/var/run/calico/wl0",
			})
			log.WithField("response", resp).Info("WorkloadAdded response")
			return err
		}).ShouldNot(HaveOccurred())

		By("Creating the per-workload socket")
		Eventually(func() error {
			_, err := os.Stat("/tmp/fvtest-calico-run/wl0/policysync.sock")
			return err
		}).ShouldNot(HaveOccurred())
		// TODO Permissions on sockets
		felix.Exec("chmod", "a+rw", "/var/run/calico/wl0/policysync.sock")

		// TODO Connect to policy sync API.

		var conn *grpc.ClientConn
		var err error
		var opts []grpc.DialOption

		opts = append(opts, grpc.WithInsecure())
		opts = append(opts, grpc.WithDialer(unixDialer))
		conn, err = grpc.Dial("/tmp/fvtest-calico-run/wl0/policysync.sock", opts...)
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
