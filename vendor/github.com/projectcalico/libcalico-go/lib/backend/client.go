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

package backend

import (
	"errors"
	"fmt"

	"github.com/projectcalico/libcalico-go/lib/api"
	bapi "github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/compat"
	"github.com/projectcalico/libcalico-go/lib/backend/etcd"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s"
	log "github.com/sirupsen/logrus"
)

// NewClient creates a new backend datastore client.
func NewClient(config api.CalicoAPIConfig) (c bapi.Client, err error) {
	log.Debugf("Using datastore type '%s'", config.Spec.DatastoreType)
	switch config.Spec.DatastoreType {
	case api.EtcdV2:
		c, err = etcd.NewEtcdClient(&config.Spec.EtcdConfig)
		if c != nil {
			// Wrap the backend, which deals only in raw KV pairs with an
			// adaptor that handles aggregate datatypes.  This allows for
			// reading and writing Profile and Node objects, which for etcdv2
			// are composed of multiple backend keys.
			//
			// This is only required for etcdv2 backend as Kuberenetes driver
			// uses the composite Profile and Node KV types.
			c = compat.NewAdaptor(c)
		}
	case api.Kubernetes:
		c, err = k8s.NewKubeClient(&config.Spec.KubeConfig)
	default:
		err = errors.New(fmt.Sprintf("Unknown datastore type: %v",
			config.Spec.DatastoreType))
	}
	return
}
