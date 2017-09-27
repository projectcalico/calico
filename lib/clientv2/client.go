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
	"encoding/hex"
	"fmt"

	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/libcalico-go/lib/backend"
	bapi "github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/ipam"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/options"
)

// client implements the client.Interface.
type client struct {
	// The backend client is currently public to allow access to datastore
	// specific functions that are used by calico/node.  This is a temporary
	// measure and users of the client API should not assume that the backend
	// will be available in the future.
	Backend bapi.Client

	// The resources client used internally.
	resources resourceInterface
}

// New returns a connected client. The ClientConfig can either be created explicitly,
// or can be loaded from a config file or environment variables using the LoadClientConfig() function.
func New(config apiconfig.CalicoAPIConfig) (Interface, error) {
	var err error
	cc := client{}
	if cc.Backend, err = backend.NewClient(config); err != nil {
		return nil, err
	}
	cc.resources = &resources{backend: cc.Backend}
	return cc, err
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
	return ipam.NewIPAM(c.Backend, poolAccessor{})
}

type poolAccessor struct {
	client *client
}

func (p poolAccessor) GetEnabledPools(ipVersion int) ([]net.IPNet, error) {
	pools, err := p.client.IPPools().List(context.Background(), options.ListOptions{})
	if err != nil {
		return nil, err
	}
	enabled := []net.IPNet{}
	for _, pool := range pools.Items {
		if pool.Spec.Disabled {
			continue
		} else if _, cidr, err := net.ParseCIDR(pool.Spec.CIDR); err != nil {
			enabled = append(enabled, *cidr)
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
	if err := c.Backend.EnsureInitialized(); err != nil {
		return err
	}

	// Ensure a cluster GUID is set for the deployment.  We do this
	// irrespective of how Calico is deployed.
	kv := &model.KVPair{
		Key:   model.GlobalConfigKey{Name: "ClusterGUID"},
		Value: fmt.Sprintf("%v", hex.EncodeToString(uuid.NewV4().Bytes())),
	}
	if _, err := c.Backend.Create(context.Background(), kv); err == nil {
		log.WithField("ClusterGUID", kv.Value).Info("Assigned cluster GUID")
	} else {
		if _, ok := err.(errors.ErrorResourceAlreadyExists); !ok {
			log.WithError(err).WithField("ClusterGUID", kv.Value).Warn("Failed to assign cluster GUID")
			return err
		}
		log.Infof("Using previously configured cluster GUID")
	}

	return nil
}
