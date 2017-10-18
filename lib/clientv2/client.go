// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package clientv2

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/libcalico-go/lib/backend"
	bapi "github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/ipam"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/options"
)

// client implements the client.Interface.
type client struct {
	// The backend client.
	backend bapi.Client

	// The resources client used internally.
	resources resourceInterface
}

// New returns a connected client. The ClientConfig can either be created explicitly,
// or can be loaded from a config file or environment variables using the LoadClientConfig() function.
func New(config apiconfig.CalicoAPIConfig) (Interface, error) {
	be, err := backend.NewClient(config)
	if err != nil {
		return nil, err
	}
	return client{
		backend:   be,
		resources: &resources{backend: be},
	}, nil
}

// NewFromEnv loads the config from ENV variables and returns a connected client.
func NewFromEnv() (Interface, error) {

	config, err := apiconfig.LoadClientConfigFromEnvironment()
	if err != nil {
		return nil, err
	}

	return New(*config)
}

// Nodes returns an interface for managing node resources.
func (c client) Nodes() NodeInterface {
	return nodes{client: c}
}

// Policies returns an interface for managing policy resources.
func (c client) NetworkPolicies() NetworkPolicyInterface {
	return networkPolicies{client: c}
}

// Policies returns an interface for managing policy resources.
func (c client) GlobalNetworkPolicies() GlobalNetworkPolicyInterface {
	return globalnetworkpolicies{client: c}
}

// IPPools returns an interface for managing IP pool resources.
func (c client) IPPools() IPPoolInterface {
	return ipPools{client: c}
}

// Profiles returns an interface for managing profile resources.
func (c client) Profiles() ProfileInterface {
	return profiles{client: c}
}

// HostEndpoints returns an interface for managing host endpoint resources.
func (c client) HostEndpoints() HostEndpointInterface {
	return hostEndpoints{client: c}
}

// WorkloadEndpoints returns an interface for managing workload endpoint resources.
func (c client) WorkloadEndpoints() WorkloadEndpointInterface {
	return workloadEndpoints{client: c}
}

// BGPPeers returns an interface for managing BGP peer resources.
func (c client) BGPPeers() BGPPeerInterface {
	return bgpPeers{client: c}
}

// IPAM returns an interface for managing IP address assignment and releasing.
func (c client) IPAM() ipam.Interface {
	return ipam.NewIPAMClient(c.backend, poolAccessor{client: &c})
}

// BGPConfigurations returns an interface for managing the BGP configuration resources.
func (c client) BGPConfigurations() BGPConfigurationInterface {
	return bgpConfigurations{client: c}
}

// FelixConfigurations returns an interface for managing the Felix configuration resources.
func (c client) FelixConfigurations() FelixConfigurationInterface {
	return felixConfigurations{client: c}
}

// ClusterInformation returns an interface for managing the cluster information resource.
func (c client) ClusterInformation() ClusterInformationInterface {
	return clusterInformation{client: c}
}

type poolAccessor struct {
	client *client
}

func (p poolAccessor) GetEnabledPools(ipVersion int) ([]net.IPNet, error) {
	pools, err := p.client.IPPools().List(context.Background(), options.ListOptions{})
	if err != nil {
		return nil, err
	}
	log.Debugf("Got list of all IPPools: %v", pools)
	enabled := []net.IPNet{}
	for _, pool := range pools.Items {
		if pool.Spec.Disabled {
			continue
		} else if _, cidr, err := net.ParseCIDR(pool.Spec.CIDR); err == nil && cidr.Version() == ipVersion {
			log.Debugf("Adding pool (%s) to the enabled IPPool list", cidr.String())
			enabled = append(enabled, *cidr)
		} else if err != nil {
			log.Warnf("Failed to parse the IPPool: %s. Ignoring that IPPool", pool.Spec.CIDR)
		} else {
			log.Debugf("Ignoring IPPool: %s. IP version is different.", pool.Spec.CIDR)
		}
	}
	return enabled, nil
}

// EnsureInitialized is used to ensure the backend datastore is correctly
// initialized for use by Calico.  This method may be called multiple times, and
// will have no effect if the datastore is already correctly initialized.
//
// Most Calico deployment scenarios will automatically implicitly invoke this
// method and so a general consumer of this API can assume that the datastore
// is already initialized.
func (c client) EnsureInitialized() error {
	// Perform datastore specific initialization first.
	if err := c.backend.EnsureInitialized(); err != nil {
		return err
	}

	return nil
}

// Backend returns the backend client used by the v2 client.  Not exposed on the main
// client API, but available publicly for consumers that require access to the backend
// client (e.g. for syncer support).
func (c client) Backend() bapi.Client {
	return c.backend
}
