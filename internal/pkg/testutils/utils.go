// Copyright (c) 2015-2019 Tigera, Inc. All rights reserved.
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
	"os"
	"strings"

	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/options"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	log "github.com/sirupsen/logrus"
)

const K8S_TEST_NS = "test"
const TEST_DEFAULT_NS = "default"

// Delete everything under /calico from etcd.
func WipeDatastore() {
	spec := apiconfig.CalicoAPIConfig{
		Spec: apiconfig.CalicoAPIConfigSpec{
			EtcdConfig: apiconfig.EtcdConfig{
				EtcdEndpoints: os.Getenv("ETCD_ENDPOINTS"),
			},
			KubeConfig: apiconfig.KubeConfig{
				K8sAPIEndpoint: os.Getenv("K8S_API_ENDPOINT"),
			},
		},
	}
	if os.Getenv("DATASTORE_TYPE") == "etcdv3" {
		spec.Spec.DatastoreType = apiconfig.EtcdV3
	} else {
		spec.Spec.DatastoreType = apiconfig.Kubernetes
	}

	be, err := backend.NewClient(spec)
	if err != nil {
		panic(err)
	}
	_ = be.Clean()

	// Set the ready flag so calls to the CNI plugin can proceed
	calicoClient, _ := client.NewFromEnv()
	newClusterInfo := api.NewClusterInformation()
	newClusterInfo.Name = "default"
	datastoreReady := true
	newClusterInfo.Spec.DatastoreReady = &datastoreReady
	ci, err := calicoClient.ClusterInformation().Create(context.Background(), newClusterInfo, options.SetOptions{})
	if err != nil {
		panic(err)
	}
	log.Printf("Set ClusterInformation: %v %v\n", ci, *ci.Spec.DatastoreReady)
}

func MustDeleteIPPool(c client.Interface, cidr string) {
	log.SetLevel(log.DebugLevel)
	log.SetOutput(os.Stderr)

	name := strings.Replace(cidr, ".", "-", -1)
	name = strings.Replace(name, ":", "-", -1)
	name = strings.Replace(name, "/", "-", -1)

	_, err := c.IPPools().Delete(context.Background(), name, options.DeleteOptions{})
	if err != nil {
		panic(err)
	}
}

// MustCreateNewIPPool creates a new Calico IPAM IP Pool.
func MustCreateNewIPPool(c client.Interface, cidr string, ipip, natOutgoing, ipam bool) string {
	return MustCreateNewIPPoolBlockSize(c, cidr, ipip, natOutgoing, ipam, 0)
}

// MustCreateNewIPPoolBlockSize creates a new Calico IPAM IP Pool with support for setting the block size.
func MustCreateNewIPPoolBlockSize(c client.Interface, cidr string, ipip, natOutgoing, ipam bool, blockSize int) string {
	log.SetLevel(log.DebugLevel)

	log.SetOutput(os.Stderr)

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

	_, err := c.IPPools().Create(context.Background(), pool, options.SetOptions{})
	if err != nil {
		panic(err)
	}
	return pool.Name
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
	err = nil
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
		newNode, err := kc.CoreV1().Nodes().Create(&n)
		if err != nil {
			if kerrors.IsAlreadyExists(err) {
				return nil
			}
		}
		log.WithField("node", newNode).WithError(err).Info("node applied")
	} else {
		// Otherwise, create it in Calico.
		n := api.NewNode()
		n.Name = host
		_, err = c.Nodes().Create(context.Background(), n, options.SetOptions{})
	}
	return err
}

func DeleteNode(c client.Interface, kc *kubernetes.Clientset, host string) error {
	var err error
	err = nil
	if os.Getenv("DATASTORE_TYPE") == "kubernetes" {
		// delete the node in Kubernetes.
		err := kc.CoreV1().Nodes().Delete(host, &metav1.DeleteOptions{})
		log.WithError(err).Info("node deleted")
	} else {
		// Otherwise, delete it in Calico.
		n := api.NewNode()
		n.Name = host
		_, err = c.Nodes().Delete(context.Background(), host, options.DeleteOptions{})
		log.WithError(err).Info("node deleted")
	}
	return err
}
