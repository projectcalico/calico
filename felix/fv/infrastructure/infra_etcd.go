// Copyright (c) 2018-2021 Tigera, Inc. All rights reserved.
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

package infrastructure

import (
	"context"
	"errors"
	"fmt"
	"os"

	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/utils"
)

type EtcdDatastoreInfra struct {
	etcdContainer *containers.Container
	bpfLog        *containers.Container

	Endpoint    string
	BadEndpoint string
}

func createEtcdDatastoreInfra() DatastoreInfra {
	infra, err := GetEtcdDatastoreInfra()
	Expect(err).NotTo(HaveOccurred())
	return infra
}

func GetEtcdDatastoreInfra() (*EtcdDatastoreInfra, error) {
	eds := &EtcdDatastoreInfra{}

	// Start etcd.
	eds.etcdContainer = RunEtcd()
	if eds.etcdContainer == nil {
		return nil, errors.New("failed to create etcd container")
	}

	// In BPF mode, start BPF logging.
	if os.Getenv("FELIX_FV_ENABLE_BPF") == "true" {
		eds.bpfLog = containers.Run("bpf-log",
			containers.RunOpts{
				AutoRemove:       true,
				IgnoreEmptyLines: true,
			},
			"--privileged",
			"calico/bpftool:v5.3-amd64", "/bpftool", "prog", "tracelog")
	}

	eds.Endpoint = fmt.Sprintf("https://%s:6443", eds.etcdContainer.IP)
	eds.BadEndpoint = fmt.Sprintf("https://%s:1234", eds.etcdContainer.IP)

	return eds, nil
}

func (eds *EtcdDatastoreInfra) GetDockerArgs() []string {
	return []string{
		"-e", "CALICO_DATASTORE_TYPE=etcdv3",
		"-e", "FELIX_DATASTORETYPE=etcdv3",
		"-e", "TYPHA_DATASTORETYPE=etcdv3",
		"-e", "TYPHA_ETCDENDPOINTS=http://" + eds.etcdContainer.IP + ":2379",
		"-e", "CALICO_ETCD_ENDPOINTS=http://" + eds.etcdContainer.IP + ":2379",
	}
}

func (eds *EtcdDatastoreInfra) GetBadEndpointDockerArgs() []string {
	return []string{
		"-e", "CALICO_DATASTORE_TYPE=etcdv3",
		"-e", "FELIX_DATASTORETYPE=etcdv3",
		"-e", "TYPHA_DATASTORETYPE=etcdv3",
		"-e", "TYPHA_ETCDENDPOINTS=http://" + eds.etcdContainer.IP + ":2379",
		"-e", "CALICO_ETCD_ENDPOINTS=http://" + eds.etcdContainer.IP + ":1234",
	}
}

func (eds *EtcdDatastoreInfra) GetCalicoClient() client.Interface {
	return utils.GetEtcdClient(eds.etcdContainer.IP)
}

func (eds *EtcdDatastoreInfra) GetClusterGUID() string {
	ci, err := eds.GetCalicoClient().ClusterInformation().Get(
		context.Background(),
		"default",
		options.GetOptions{},
	)
	Expect(err).NotTo(HaveOccurred())
	return ci.Spec.ClusterGUID
}

func (eds *EtcdDatastoreInfra) SetExpectedIPIPTunnelAddr(felix *Felix, idx int, needBGP bool) {
	if needBGP {
		felix.ExpectedIPIPTunnelAddr = fmt.Sprintf("10.65.%d.1", idx)
		felix.ExtraSourceIPs = append(felix.ExtraSourceIPs, felix.ExpectedIPIPTunnelAddr)
	}
}

func (eds *EtcdDatastoreInfra) SetExpectedVXLANTunnelAddr(felix *Felix, idx int, needBGP bool) {
	if needBGP {
		felix.ExpectedVXLANTunnelAddr = fmt.Sprintf("10.65.%d.0", idx)
	}
}

func (eds *EtcdDatastoreInfra) SetExpectedVXLANV6TunnelAddr(felix *Felix, idx int, needBGP bool) {
	if needBGP {
		felix.ExpectedVXLANV6TunnelAddr = fmt.Sprintf("dead:beef::%d:0", idx)
	}
}

func (eds *EtcdDatastoreInfra) SetExpectedWireguardTunnelAddr(felix *Felix, idx int, needWireguard bool) {
	if needWireguard {
		// Set to be the same as IPIP.
		felix.ExpectedWireguardTunnelAddr = fmt.Sprintf("10.65.%d.1", idx)
	}
}

func (eds *EtcdDatastoreInfra) RemoveNodeAddresses(felix *Felix) {
	node, err := eds.GetCalicoClient().Nodes().Get(utils.Ctx, felix.Hostname, options.GetOptions{})
	if err != nil {
		panic(err)
	}
	node.Spec.Addresses = []libapi.NodeAddress{}
	_, err = eds.GetCalicoClient().Nodes().Update(utils.Ctx, node, utils.NoOptions)
	if err != nil {
		panic(err)
	}
}

func (eds *EtcdDatastoreInfra) AddNode(felix *Felix, idx int, needBGP bool) {
	felixNode := libapi.NewNode()
	felixNode.Name = felix.Hostname
	felixNode.Spec.IPv4VXLANTunnelAddr = felix.ExpectedVXLANTunnelAddr
	felixNode.Spec.IPv6VXLANTunnelAddr = felix.ExpectedVXLANV6TunnelAddr
	if needBGP {
		felixNode.Spec.BGP = &libapi.NodeBGPSpec{
			IPv4Address:        fmt.Sprintf("%s/%s", felix.IP, felix.IPPrefix),
			IPv4IPIPTunnelAddr: felix.ExpectedIPIPTunnelAddr,
		}
		if len(felix.IPv6) > 0 {
			felixNode.Spec.BGP.IPv6Address = fmt.Sprintf("%s/%s", felix.IPv6, felix.IPv6Prefix)
		}
	}
	nodeAddress := libapi.NodeAddress{Address: felix.IP, Type: libapi.InternalIP}
	felixNode.Spec.Addresses = append(felixNode.Spec.Addresses, nodeAddress)
	if len(felix.IPv6) > 0 {
		nodeAddressV6 := libapi.NodeAddress{Address: felix.IPv6, Type: libapi.InternalIP}
		felixNode.Spec.Addresses = append(felixNode.Spec.Addresses, nodeAddressV6)
	}
	Eventually(func() error {
		_, err := eds.GetCalicoClient().Nodes().Create(utils.Ctx, felixNode, utils.NoOptions)
		if err != nil {
			log.WithError(err).Warn("Failed to create node")
		}
		return err
	}, "10s", "500ms").ShouldNot(HaveOccurred())
}

func (eds *EtcdDatastoreInfra) AddWorkload(wep *libapi.WorkloadEndpoint) (*libapi.WorkloadEndpoint, error) {
	return eds.GetCalicoClient().WorkloadEndpoints().Create(utils.Ctx, wep, utils.NoOptions)
}

func (eds *EtcdDatastoreInfra) RemoveWorkload(ns string, name string) error {
	_, err := eds.GetCalicoClient().WorkloadEndpoints().Delete(utils.Ctx, ns, name, options.DeleteOptions{})
	return err
}

func (eds *EtcdDatastoreInfra) AddAllowToDatastore(selector string) error {
	// Create a policy to allow egress from the host so that we don't cut off Felix's datastore connection
	// when we enable the host endpoint.
	policy := api.NewGlobalNetworkPolicy()
	policy.Name = "allow-egress"
	policy.Spec.Selector = selector
	policy.Spec.Egress = []api.Rule{{
		Action: api.Allow,
		Destination: api.EntityRule{
			Nets: []string{eds.etcdContainer.IP + "/32"},
		},
	}}
	_, err := eds.GetCalicoClient().GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
	return err
}

func (eds *EtcdDatastoreInfra) AddDefaultAllow() string {
	defaultProfile := api.NewProfile()
	defaultProfile.Name = "default"
	defaultProfile.Spec.LabelsToApply = map[string]string{"default": ""}
	defaultProfile.Spec.Egress = []api.Rule{{Action: api.Allow}}
	defaultProfile.Spec.Ingress = []api.Rule{{Action: api.Allow}}
	_, err := eds.GetCalicoClient().Profiles().Create(utils.Ctx, defaultProfile, utils.NoOptions)
	Expect(err).NotTo(HaveOccurred())
	return defaultProfile.Name
}

func (eds *EtcdDatastoreInfra) AddDefaultDeny() error {
	return nil
}

func (eds *EtcdDatastoreInfra) DumpErrorData() {
	eds.etcdContainer.Exec("etcdctl", "get", "/", "--prefix", "--keys-only")
}

func (eds *EtcdDatastoreInfra) Stop() {
	eds.bpfLog.StopLogs()
	eds.etcdContainer.StopLogs()
	eds.bpfLog.Stop()
	eds.etcdContainer.Stop()
}
