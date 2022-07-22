// Copyright (c) 2015-2021 Tigera, Inc. All rights reserved.
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
package testutils

import (
	"context"
	"fmt"
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"

	log "github.com/sirupsen/logrus"
)

const (
	K8S_TEST_NS     = "test"
	TEST_DEFAULT_NS = "default"
)

// Delete everything under /calico from etcd.
func WipeDatastore() {
	cfg, err := apiconfig.LoadClientConfigFromEnvironment()
	if err != nil {
		panic(err)
	}

	be, err := backend.NewClient(*cfg)
	if err != nil {
		panic(err)
	}
	err = be.Clean()
	if err != nil {
		panic(err)
	}

	// Set the ready flag so calls to the CNI plugin can proceed
	calicoClient, err := client.New(*cfg)
	if err != nil {
		panic(err)
	}
	newClusterInfo := api.NewClusterInformation()
	newClusterInfo.Name = "default"
	datastoreReady := true
	newClusterInfo.Spec.DatastoreReady = &datastoreReady
	ci, err := calicoClient.ClusterInformation().Create(context.Background(), newClusterInfo, options.SetOptions{})
	if err != nil {
		panic(err)
	}
	log.Debugf("Set ClusterInformation: %v %v", ci, *ci.Spec.DatastoreReady)
}

// MustCreateNewIPPool creates a new Calico IPAM IP Pool.
func MustCreateNewIPPool(c client.Interface, cidr string, ipip, natOutgoing, ipam bool) string {
	return MustCreateNewIPPoolBlockSize(c, cidr, ipip, natOutgoing, ipam, 0)
}

// MustCreateNewIPPoolBlockSize creates a new Calico IPAM IP Pool with support for setting the block size.
func MustCreateNewIPPoolBlockSize(c client.Interface, cidr string, ipip, natOutgoing, ipam bool, blockSize int) string {
	name := strings.Replace(cidr, ".", "-", -1)
	name = strings.Replace(name, ":", "-", -1)
	name = strings.Replace(name, "/", "-", -1)
	var mode api.IPIPMode
	if ipip {
		mode = api.IPIPModeAlways
	} else {
		mode = api.IPIPModeNever
	}

	pool := api.NewIPPool()
	pool.Name = name
	pool.Spec.CIDR = cidr
	pool.Spec.NATOutgoing = natOutgoing
	pool.Spec.Disabled = !ipam
	pool.Spec.IPIPMode = mode
	pool.Spec.BlockSize = blockSize

	By(fmt.Sprintf("Creating IP pool %s for the test. %+v", name, pool.Spec))
	_, err := c.IPPools().Create(context.Background(), pool, options.SetOptions{})
	if err != nil {
		panic(err)
	}
	return pool.Name
}

func MustDeleteIPPool(c client.Interface, cidr string) {
	name := strings.Replace(cidr, ".", "-", -1)
	name = strings.Replace(name, ":", "-", -1)
	name = strings.Replace(name, "/", "-", -1)

	_, err := c.IPPools().Delete(context.Background(), name, options.DeleteOptions{})
	if err != nil {
		panic(err)
	}
}

// Used for passing arguments to the CNI plugin.
type cniArgs struct {
	Env []string
}

func (c *cniArgs) AsEnv() []string {
	return c.Env
}

func AddNode(c client.Interface, kc *kubernetes.Clientset, host string) error {
	var err error
	if os.Getenv("DATASTORE_TYPE") == "kubernetes" {
		// create the node in Kubernetes.
		n := corev1.Node{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Node",
				APIVersion: "v1",
			},
		}
		n.Name = host

		// Create/Update the node
		_, err := kc.CoreV1().Nodes().Create(context.Background(), &n, metav1.CreateOptions{})
		if err != nil {
			if kerrors.IsAlreadyExists(err) {
				log.WithField("node", host).Info("Node already exists")
				return nil
			}
		}
		log.WithField("node", host).WithError(err).Info("Node created")
	} else {
		// Otherwise, create it in Calico.
		n := libapi.NewNode()
		n.Name = host
		_, err = c.Nodes().Create(context.Background(), n, options.SetOptions{})
		if err != nil {
			log.WithField("node", host).WithError(err).Warn("Error creating node")
		}
	}
	return err
}

func DeleteNode(c client.Interface, kc *kubernetes.Clientset, host string) error {
	var err error
	if os.Getenv("DATASTORE_TYPE") == "kubernetes" {
		// delete the node in Kubernetes.
		err = kc.CoreV1().Nodes().Delete(context.Background(), host, metav1.DeleteOptions{})
		log.WithError(err).WithField("node", host).Debug("Kubernetes node deleted")
	} else {
		// Otherwise, delete it in Calico.
		n := libapi.NewNode()
		n.Name = host
		_, err = c.Nodes().Delete(context.Background(), host, options.DeleteOptions{})
		log.WithError(err).WithField("node", host).Debug("Calico node deleted")
	}
	if _, ok := err.(errors.ErrorResourceDoesNotExist); ok || kerrors.IsNotFound(err) {
		// Ignore does not exist.
		return nil
	}
	return err
}
