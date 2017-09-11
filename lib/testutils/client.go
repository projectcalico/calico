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
	etcdclient "github.com/coreos/etcd/client"
	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/libcalico-go/lib/backend"
	log "github.com/sirupsen/logrus"

	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"golang.org/x/net/context"
)

func CleanDatastore(config apiconfig.CalicoAPIConfig) {
	var err error

	log.Println(fmt.Sprintf("Cleaning datastore: %v", config.Spec.DatastoreType))

	switch config.Spec.DatastoreType {
	case apiconfig.EtcdV2:
		// To clean etcd, just create a new etcd client and delete the entire calico tree.
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
	case apiconfig.Kubernetes:
		// To clean Kuberenetes, we create a Client and use the backend interface to
		// list and remove each of the resource types currently supported by the KDD.  We
		// can't remove everything though because some of the resources are owned by Kubernetes.
		backend, _ := backend.NewClient(config)

		types := []model.ListInterface{
			model.GlobalBGPConfigListOptions{},
			model.NodeBGPConfigListOptions{},
			model.GlobalBGPPeerListOptions{},
			model.NodeBGPPeerListOptions{},
			model.GlobalConfigListOptions{},
			model.IPPoolListOptions{},
		}
		for _, t := range types {
			rs, _ := backend.List(t, "")
			for _, r := range rs.KVPairs {
				log.WithField("Key", r.Key).Info("Deleting from KDD")
				backend.Delete(r.Key, r.Revision)
			}
		}

	default:
		err = errors.New(fmt.Sprintf("Unknown datastore type: %v", config.Spec.DatastoreType))
	}

	if err != nil {
		panic(err)
	}
}

// DumpDatastore prints out a recursive dump of the contents of backend.
func DumpDatastore(config apiconfig.CalicoAPIConfig) error {
	var output []byte
	var err error

	log.Println(fmt.Sprintf("Dumping datastore: %v", config.Spec.DatastoreType))

	switch config.Spec.DatastoreType {
	case apiconfig.EtcdV2:
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
