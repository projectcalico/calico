// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

package client_test

import (
	"fmt"
	"log"
	"os"
	"os/exec"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/onsi/ginkgo/extensions/table"

	"github.com/tigera/libcalico-go/calicoctl/commands"
	"github.com/tigera/libcalico-go/lib/api"
	"github.com/tigera/libcalico-go/lib/backend/etcd"
	"github.com/tigera/libcalico-go/lib/client"
)

var etcdType api.BackendType

var args = []client.AutoAssignArgs{
	{
		Num4: 0,
		Num6: 20,
		//Hostname: "notMac",
	},
	{
		Num4: 4,
		Num6: 10,
	},
	{
		Num4: 1,
		Num6: 0,
	},
	{
		Num4: 0,
		Num6: 256,
	},

	{
		Num4:     4,
		Num6:     254,
		Hostname: "notMac",
	},
	{
		Num4: 1,
		Num6: 0,
	},
}

func testIPAM(inv4, inv6 int, host string, setup bool) (int, int) {
	fmt.Println("in func")

	etcdType = "etcdv2"

	etcdConfig := etcd.EtcdConfig{
		EtcdEndpoints: "http://127.0.0.1:2379",
	}
	ac := api.ClientConfig{BackendType: etcdType, BackendConfig: &etcdConfig} //etcdType.NewConfig()}

	bc, err := client.New(ac)
	if err != nil {
		panic(err)
	}

	ic := bc.IPAM()

	entry := client.AutoAssignArgs{
		Num4:     inv4,
		Num6:     inv6,
		Hostname: host,
	}
	if setup {
		setupEnv()
	}

	v4, v6, outErr := ic.AutoAssign(entry)

	if outErr != nil {
		fmt.Print("printing error.... ")
		fmt.Println(outErr)
	}

	return len(v4), len(v6)

}

var _ = Describe("IPAM", func() {

	DescribeTable("requested IPs vs got IPs",
		func(host string, setup bool, inv4, inv6, expv4, expv6 int) {
			outv4, outv6 := testIPAM(inv4, inv6, host, setup)
			//fmt.Println(outv4, outv6)
			Expect(outv4).To(Equal(expv4))
			Expect(outv6).To(Equal(expv6))
		},
		Entry("1 v4 1 v6", "testHost", true, 1, 1, 1, 1),
		Entry("256 v4 256 v6", "testHost", true, 256, 256, 256, 256),
		Entry("257 v4 0 v6", "testHost", true, 257, 0, 256, 0),
		Entry("0 v4 257 v6", "testHost", true, 0, 257, 0, 256),
	)

})

func setupEnv() {

	cmd := "docker"
	argsRm := []string{"rm", "-f", "calico-etcd"}
	if err := exec.Command(cmd, argsRm...).Run(); err != nil {
		log.Println(err)
	}

	argsRun := []string{"run", "--detach", "-p", "2379:2379", "--name", "calico-etcd", "quay.io/coreos/etcd:v2.3.6", "--advertise-client-urls", "http://127.0.0.1:2379,http://127.0.0.1:4001", "--listen-client-urls", "http://0.0.0.0:2379,http://0.0.0.0:4001"}
	if err := exec.Command(cmd, argsRun...).Run(); err != nil {
		log.Println(err)
		os.Exit(1)
	}

	argsPool := []string{"create", "-f", "../../test/pool1.yaml"}
	if err := commands.Create(argsPool); err != nil {
		log.Println(err)
		os.Exit(1)
	}

}

// ctx := context.Background()

// dockerClient, err := docker.NewEnvClient()
// if err != nil {
// 	log.Fatalf("error creating docker client: %s", err)
// }

// options := types.ContainerRemoveOptions{
// 	//RemoveLinks:   true,
// 	RemoveVolumes: true,
// 	Force:         true,
// }
// if err := dockerClient.ContainerRemove(ctx, "calico-etcd", options); err != nil {
// 	log.Printf("Error removing container: %s\n", err)
// }

// port := make(nat.PortSet)
// port2379, err := nat.NewPort("tcp", "2379")
// if err != nil {
// 	log.Printf("Error creating NAT port: %v", err)
// }
// port[port2379] = struct{}{}

// env := []string{
// 	"ETCD_ADVERTISE_CLIENT_URLS=http://127.0.0.1:2379,http://127.0.0.1:4001",
// 	"ETCD_LISTEN_CLIENT_URLS=http://0.0.0.0:2379,http://0.0.0.0:4001",
// }

// config := &container.Config{
// 	ExposedPorts:    port,
// 	Env:             env,
// 	Image:           "quay.io/coreos/etcd:v2.3.6",
// 	NetworkDisabled: false,
// }
// portMap := make(nat.PortMap)
// portMap[port2379] = []nat.PortBinding{{HostIP: "127.0.0.1", HostPort: "2379"}}

// hostConfig := &container.HostConfig{
// 	PortBindings: portMap,
// }

// resp, err := dockerClient.ContainerCreate(context.Background(), config, hostConfig, nil, "calico-etcd")
// if err != nil {

// 	log.Printf("Error creating container: %v", err)

// }
// err = dockerClient.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{})
// if err != nil {
// 	log.Printf("Error starting the container: %v", err)
// }

// pool := api.NewPool()
// pool.Metadata.CIDR =
// 	client.Pools().Create(pool)
