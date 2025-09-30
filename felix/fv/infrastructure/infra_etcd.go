// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.
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
	"net"
	"os"

	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/utils"
	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

type EtcdDatastoreInfra struct {
	EtcdContainer *containers.Container
	bpfLog        *containers.Container
	client        client.Interface

	Endpoint    string
	BadEndpoint string

	cleanups cleanupStack
	felixes  []*Felix
}

func createEtcdDatastoreInfra(opts ...CreateOption) DatastoreInfra {
	infra, err := GetEtcdDatastoreInfra()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return infra
}

func GetEtcdDatastoreInfra() (*EtcdDatastoreInfra, error) {
	eds := &EtcdDatastoreInfra{}

	// Start etcd.
	eds.EtcdContainer = RunEtcd()
	if eds.EtcdContainer == nil {
		return nil, errors.New("failed to create etcd container")
	}
	// Ensure etcd is stopped via cleanup stack.
	eds.AddCleanup(func() {
		if eds.EtcdContainer != nil {
			eds.EtcdContainer.StopLogs()
			eds.EtcdContainer.Stop()
		}
	})

	// In BPF mode, start BPF logging.
	if os.Getenv("FELIX_FV_ENABLE_BPF") == "true" {
		eds.bpfLog = RunBPFLog()
		eds.AddCleanup(func() {
			if eds.bpfLog != nil {
				eds.bpfLog.StopLogs()
				eds.bpfLog.Stop()
			}
		})
	}

	// Ensure client is closed via cleanup stack (if it was created).
	eds.AddCleanup(func() {
		if eds.client != nil {
			if err := eds.client.Close(); err != nil {
				log.WithError(err).Warn("Client Close() returned an error.  Ignoring.")
			}
		}
	})

	eds.Endpoint = fmt.Sprintf("https://%s:6443", eds.EtcdContainer.IP)
	eds.BadEndpoint = fmt.Sprintf("https://%s:1234", eds.EtcdContainer.IP)

	return eds, nil
}

func (eds *EtcdDatastoreInfra) GetDockerArgs() []string {
	return []string{
		"-e", "CALICO_DATASTORE_TYPE=etcdv3",
		"-e", "FELIX_DATASTORETYPE=etcdv3",
		"-e", "TYPHA_DATASTORETYPE=etcdv3",
		"-e", "TYPHA_ETCDENDPOINTS=http://" + eds.EtcdContainer.IP + ":2379",
		"-e", "CALICO_ETCD_ENDPOINTS=http://" + eds.EtcdContainer.IP + ":2379",
	}
}

func (eds *EtcdDatastoreInfra) GetBadEndpointDockerArgs() []string {
	return []string{
		"-e", "CALICO_DATASTORE_TYPE=etcdv3",
		"-e", "FELIX_DATASTORETYPE=etcdv3",
		"-e", "TYPHA_DATASTORETYPE=etcdv3",
		"-e", "TYPHA_ETCDENDPOINTS=http://" + eds.EtcdContainer.IP + ":2379",
		"-e", "CALICO_ETCD_ENDPOINTS=http://" + eds.EtcdContainer.IP + ":1234",
	}
}

func (eds *EtcdDatastoreInfra) GetCalicoClient() client.Interface {
	if eds.client == nil {
		eds.client = utils.GetEtcdClient(eds.EtcdContainer.IP)
	}
	return eds.client
}

func (eds *EtcdDatastoreInfra) GetClusterGUID() string {
	ci, err := eds.GetCalicoClient().ClusterInformation().Get(
		context.Background(),
		"default",
		options.GetOptions{},
	)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return ci.Spec.ClusterGUID
}

func (eds *EtcdDatastoreInfra) SetExpectedIPIPTunnelAddr(felix *Felix, ip string, needBGP bool) {
	if needBGP {
		felix.ExpectedIPIPTunnelAddr = ip
		felix.ExtraSourceIPs = append(felix.ExtraSourceIPs, felix.ExpectedIPIPTunnelAddr)
	}
}

func (eds *EtcdDatastoreInfra) SetExpectedVXLANTunnelAddr(felix *Felix, ip string) {
	felix.ExpectedVXLANTunnelAddr = ip
}

func (eds *EtcdDatastoreInfra) SetExpectedVXLANV6TunnelAddr(felix *Felix, ip string) {
	felix.ExpectedVXLANV6TunnelAddr = ip
}

func (eds *EtcdDatastoreInfra) SetExpectedWireguardTunnelAddr(felix *Felix, cidr *net.IPNet, idx int, needWireguard bool) {
	if needWireguard {
		// Set to be the same as IPIP.
		felix.ExpectedWireguardTunnelAddr = fmt.Sprintf("%d.%d.%d.1", cidr.IP[0], cidr.IP[1], idx)
	}
}

func (eds *EtcdDatastoreInfra) SetExpectedWireguardV6TunnelAddr(felix *Felix, cidr *net.IPNet, idx int, needWireguard bool) {
	if needWireguard {
		felix.ExpectedWireguardV6TunnelAddr = fmt.Sprintf("%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%d:0", cidr.IP[0], cidr.IP[1], cidr.IP[2], cidr.IP[3], cidr.IP[4], cidr.IP[5], cidr.IP[6], cidr.IP[7], cidr.IP[8], cidr.IP[9], cidr.IP[10], cidr.IP[11], idx)
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

func (eds *EtcdDatastoreInfra) AddNode(felix *Felix, v4CIDR *net.IPNet, v6CIDR *net.IPNet, idx int, needBGP bool) {
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
	gomega.Eventually(func() error {
		_, err := eds.GetCalicoClient().Nodes().Create(utils.Ctx, felixNode, utils.NoOptions)
		if err != nil {
			log.WithError(err).Warn("Failed to create node")
		}
		return err
	}, "10s", "500ms").ShouldNot(gomega.HaveOccurred())
}

func (eds *EtcdDatastoreInfra) AddWorkload(wep *libapi.WorkloadEndpoint) (*libapi.WorkloadEndpoint, error) {
	return eds.GetCalicoClient().WorkloadEndpoints().Create(utils.Ctx, wep, utils.NoOptions)
}

func (eds *EtcdDatastoreInfra) RemoveWorkload(ns string, name string) error {
	_, err := eds.GetCalicoClient().WorkloadEndpoints().Delete(utils.Ctx, ns, name, options.DeleteOptions{})
	return err
}

func (eds *EtcdDatastoreInfra) UpdateWorkload(wep *libapi.WorkloadEndpoint) (*libapi.WorkloadEndpoint, error) {
	return eds.GetCalicoClient().WorkloadEndpoints().Update(utils.Ctx, wep, options.SetOptions{})
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
			Nets: []string{eds.EtcdContainer.IP + "/32"},
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
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return defaultProfile.Name
}

func (eds *EtcdDatastoreInfra) AddDefaultDeny() error {
	return nil
}

func (eds *EtcdDatastoreInfra) DumpErrorData() {
	// Per-Felix diagnostics first for context.
	for _, f := range eds.felixes {
		if f != nil {
			dumpFelixDiags(f)
		}
	}
	// Etcd datastore contents (keys only) for quick overview.
	eds.EtcdContainer.Exec("etcdctl", "get", "/", "--prefix", "--keys-only")
}

func (eds *EtcdDatastoreInfra) Stop() {
	// Collect diagnostics first, before tearing anything down.
	if ginkgo.CurrentGinkgoTestDescription().Failed {
		eds.DumpErrorData()
	}
	// Run registered teardowns (reverse order). Do not suppress panics.
	eds.cleanups.Run()
}

func (eds *EtcdDatastoreInfra) AddCleanup(f func()) {
	eds.cleanups.Add(f)
}

func (eds *EtcdDatastoreInfra) RegisterFelix(f *Felix) {
	if f == nil {
		return
	}
	eds.felixes = append(eds.felixes, f)
}
