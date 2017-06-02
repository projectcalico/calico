// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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
	"net"

	log "github.com/Sirupsen/logrus"
	etcdclient "github.com/coreos/etcd/client"
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/api/unversioned"
	"github.com/projectcalico/libcalico-go/lib/client"
	cnet "github.com/projectcalico/libcalico-go/lib/net"

	"errors"
	"fmt"
	"os/exec"
	"strings"

	"golang.org/x/net/context"
)

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

func CreateClient(config api.CalicoAPIConfig) *client.Client {
	c, err := client.New(config)

	if err != nil {
		panic(err)
	}

	return c
}

func CleanIPPools(c *client.Client) {
	if pools, err := c.IPPools().List(api.IPPoolMetadata{}); err == nil {
		for _, pool := range pools.Items {
			if err := c.IPPools().Delete(pool.Metadata); err != nil {
				panic(err)
			}
		}
	}
}

func CleanDatastore(config api.CalicoAPIConfig) {
	var err error

	log.Println(fmt.Sprintf("Cleaning datastore: %v", config.Spec.DatastoreType))

	switch config.Spec.DatastoreType {
	case api.EtcdV2:
		cfg := etcdclient.Config{
			Endpoints: []string{config.Spec.EtcdScheme + "://" + config.Spec.EtcdAuthority},
		}
		if config.Spec.EtcdEndpoints != "" {
			cfg = etcdclient.Config{
				Endpoints: strings.Split(config.Spec.EtcdEndpoints, ","),
			}
		}
		if c, err := etcdclient.New(cfg); c != nil {
			kapi := etcdclient.NewKeysAPI(c)
			_, err = kapi.Delete(context.Background(), "/calico", &etcdclient.DeleteOptions{Dir: true, Recursive: true})
		} else {
			log.Errorf("Can't create etcd backend %v", err)
		}
	default:
		err = errors.New(fmt.Sprintf("Unknown datastore type: %v", config.Spec.DatastoreType))
	}

	if err != nil {
		panic(err)
	}
}

// CreateCleanClient is a utility function to wipe clean "/calico" recursively from backend
// and to return confugred client to it
func CreateCleanClient(config api.CalicoAPIConfig) *client.Client {
	CleanDatastore(config)

	return CreateClient(config)
}

// DumpDatastore prints out a recursive dump of the contents of backend.
func DumpDatastore(config api.CalicoAPIConfig) error {
	var output []byte
	var err error

	log.Println(fmt.Sprintf("Dumping datastore: %v", config.Spec.DatastoreType))

	switch config.Spec.DatastoreType {
	case api.EtcdV2:
		output, err = exec.Command("curl", "http://127.0.0.1:2379/v2/keys?recursive=true").Output()
	default:
		err = errors.New(fmt.Sprintf("Unknown datastore type: %v", config.Spec.DatastoreType))
	}

	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			log.Printf("Dump backend return error: %s, %v", string(ee.Stderr), *ee.ProcessState)
		} else {
			log.Println(err)
		}
	} else {
		log.Println(string(output))
	}

	return err
}
