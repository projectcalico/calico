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

package infrastructure

import (
	"errors"
	"fmt"

	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/felix/fv/utils"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
)

type EtcdDatastoreInfra struct {
	etcdContainer *containers.Container

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

func (eds *EtcdDatastoreInfra) SetExpectedIPIPTunnelAddr(felix *Felix, idx int, needBGP bool) {
	if needBGP {
		felix.ExpectedIPIPTunnelAddr = fmt.Sprintf("10.65.%d.1", idx)
	}
}

func (eds *EtcdDatastoreInfra) AddNode(felix *Felix, idx int, needBGP bool) {
	felixNode := api.NewNode()
	felixNode.Name = felix.Hostname
	if needBGP {
		felixNode.Spec.BGP = &api.NodeBGPSpec{
			IPv4Address:        felix.IP,
			IPv4IPIPTunnelAddr: felix.ExpectedIPIPTunnelAddr,
		}
	}
	Eventually(func() error {
		_, err := eds.GetCalicoClient().Nodes().Create(utils.Ctx, felixNode, utils.NoOptions)
		if err != nil {
			log.WithError(err).Warn("Failed to create node")
		}
		return err
	}, "10s", "500ms").ShouldNot(HaveOccurred())
}

func (eds *EtcdDatastoreInfra) AddWorkload(wep *api.WorkloadEndpoint) (*api.WorkloadEndpoint, error) {
	return eds.GetCalicoClient().WorkloadEndpoints().Create(utils.Ctx, wep, utils.NoOptions)
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

func (eds *EtcdDatastoreInfra) AddDefaultAllow() error {
	defaultProfile := api.NewProfile()
	defaultProfile.Name = "default"
	defaultProfile.Spec.LabelsToApply = map[string]string{"default": ""}
	defaultProfile.Spec.Egress = []api.Rule{{Action: api.Allow}}
	defaultProfile.Spec.Ingress = []api.Rule{{Action: api.Allow}}
	_, err := eds.GetCalicoClient().Profiles().Create(utils.Ctx, defaultProfile, utils.NoOptions)
	return err
}

func (eds *EtcdDatastoreInfra) AddDefaultDeny() error {
	return nil
}

func (eds *EtcdDatastoreInfra) DumpErrorData() {
	eds.etcdContainer.Exec("etcdctl", "ls", "--recursive", "/")
}

func (eds *EtcdDatastoreInfra) Stop() {
	eds.etcdContainer.Stop()
}
