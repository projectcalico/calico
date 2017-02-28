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

package testutils

import (
	"log"
	"net"
	"os"

	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/api/unversioned"
	"github.com/projectcalico/libcalico-go/lib/client"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
)

// NewClient is a util function to create a new default client.
// When passed empty string, it loads the default config instead from a config file.
func NewClient(cf string) (*client.Client, error) {
	if _, err := os.Stat(cf); err != nil {
		cf = ""
	}

	cfg, err := client.LoadClientConfig(cf)
	if err != nil {
		return nil, err
	}

	c, err := client.New(*cfg)
	if err != nil {
		return nil, err
	}

	return c, err
}

// CreateNewIPPool takes a client.Client with a poolSubnet CIDR (in "192.168.1.0/24" format) with
// ipip, natOut, and ipam bools for the pool to be setup and creates a new pool.
func CreateNewIPPool(c client.Client, poolSubnet string, ipip, natOut, ipam bool) {

	_, cidr, err := net.ParseCIDR(poolSubnet)
	if err != nil {
		log.Printf("Error parsing CIDR: %s\n", err)
	}

	pool := api.IPPool{
		TypeMetadata: unversioned.TypeMetadata{
			Kind:       "pool",
			APIVersion: "v1",
		},
		Metadata: api.IPPoolMetadata{
			ObjectMetadata: unversioned.ObjectMetadata{},
			CIDR:           cnet.IPNet{*cidr},
		},
		Spec: api.IPPoolSpec{
			IPIP: &api.IPIPConfiguration{
				Enabled: ipip,
			},
			NATOutgoing: natOut,
			Disabled:    !ipam,
		},
	}

	_, err = c.IPPools().Create(&pool)

	if err != nil {
		log.Printf("Error creating pool: %s\n", err)
	}

}

// CleanIPPools removes all IP pool configuration from the datastore.
func CleanIPPools(c *client.Client) {
	if pools, err := c.IPPools().List(api.IPPoolMetadata{}); err == nil {
		for _, pool := range pools.Items {
			if err := c.IPPools().Delete(pool.Metadata); err != nil {
				panic(err)
			}
		}
	} else {
		panic(err)
	}
}
