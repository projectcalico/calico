// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

package kddipam

import (
	"context"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/kube-controllers/pkg/config"
	"github.com/projectcalico/kube-controllers/pkg/controllers/controller"
	bapi "github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
)

// Controller implements the Controller interface.  It is responsible for monitoring
// kubernetes nodes and responding to delete events by removing them from the Calico datastore.
type Controller struct {
	ctx       context.Context
	informer  cache.Controller
	indexer   cache.Indexer
	client    client.Interface
	clientset *kubernetes.Clientset
	bc        bapi.Client
}

type allocation struct {
	handle     string
	attributes map[string]string
}

// NewController Constructor for Controller
func NewController(ctx context.Context, clientset *kubernetes.Clientset, c client.Interface, cfg *config.Config) controller.Controller {
	// Used to extract the backend client we need for IPAM calls.
	type accessor interface {
		Backend() bapi.Client
	}

	nc := &Controller{
		ctx:       ctx,
		client:    c,
		bc:        c.(accessor).Backend(),
		clientset: clientset,
	}

	return nc
}

// Run starts the node controller. It does start-of-day preparation
// and then launches worker threads. We ignore reconcilerPeriod and threadiness
// as this controller does not use a cache and runs only one worker thread.
func (c *Controller) Run(threadiness int, reconcilerPeriod string, stopCh chan struct{}) {
	defer uruntime.HandleCrash()

	log.Info("Starting Kubernetes IPAM controller")

	log.Info("Kubernetes IPAM controller is now running")
	go c.run()

	<-stopCh
	log.Info("Stopping Kubernetes IPAM controller")
}

func (c *Controller) run() {
	for {
		err := c.gc()
		if err != nil {
			log.WithError(err).Error("Error performing IPAM gc")
		}
		time.Sleep(5 * time.Second)
	}
}

func (c *Controller) gc() error {
	// Query all IPAM blocks in the cluster.
	blocks, err := c.bc.List(c.ctx, model.BlockListOptions{}, "")
	if err != nil {
		return err
	}

	// Build a list of all the nodes in the cluster based on IPAM allocations across all
	// blocks, plus affinities.
	nodes := map[string][]allocation{}
	for _, kvp := range blocks.KVPairs {
		// Go through each IPAM allocation, check its attributes for the node it is assigned to.
		b := kvp.Value.(*model.AllocationBlock)
		for _, idx := range b.Allocations {
			if idx == nil {
				// Not allocated.
				continue
			}
			attr := b.Attributes[*idx]

			// Include affinity if it exists. We want to track nodes even
			// if there are no IPs actually assigned to that node.
			if b.Affinity != nil {
				n := strings.TrimLeft(*b.Affinity, "host:")
				if _, ok := nodes[n]; !ok {
					nodes[n] = []allocation{}
				}
			}

			// Track nodes based on IP allocations.
			if val, ok := attr.AttrSecondary["node"]; ok {
				if _, ok := nodes[val]; !ok {
					nodes[val] = []allocation{}
				}

				// If there is no handle, then skip this IP.
				if attr.AttrPrimary == nil {
					log.Warnf("Skipping IP with no handle")
					continue
				}

				// Calculate the IP address for this ordinal and map it to
				// the node on which it is assigned.
				nodes[val] = append(nodes[val], allocation{
					handle:     *attr.AttrPrimary,
					attributes: attr.AttrSecondary,
				})
			}
		}
	}
	log.Debugf("Nodes in IPAM: %s", nodes)

	// For each node present in IPAM, if it doesn't exist in the Kubernetes API then we
	// should consider it a candidate for cleanup.
	for node, allocations := range nodes {
		// Check if it exists in the Kubernetes API.
		// If it does, we can remove it.
		logc := log.WithField("node", node)
		if c.nodeExists(node) {
			logc.Debug("Node still exists, continue")
			continue
		}

		// Node exists in IPAM but not in the Kubernetes API. Go through each IP address and
		// check to see if the pod it references exists. If it doesn't, then release it.
		canDelete := true
		for _, a := range allocations {
			ns := a.attributes["namespace"]
			pod := a.attributes["pod"]

			if ns == "" || pod == "" {
				log.Warnf("IP allocation does not have a namespace/pod associated")
				continue
			}

			// Check to see if the pod still exists. If it does, then we shouldn't clean up
			// this node, since it might come back online.
			if c.podExists(pod, ns) {
				logc.WithFields(log.Fields{"pod": pod, "ns": ns}).Debugf("Pod still exists")
				canDelete = false
				break
			}
		}

		if !canDelete {
			logc.Infof("Can't cleanup node yet - pods still exist")
			continue
		}
		logc.Info("Cleaning up IPAM resources for deleted node")

		// Release the affinities for this node.
		if err = c.client.IPAM().ReleaseHostAffinities(c.ctx, node); err != nil {
			logc.WithError(err).Errorf("Failed to release node affinity")
		}
		logc.Debug("Released all affinities for node")

		// At this point, we've verified that the node isn't in Kubernetes and that all the allocations
		// are tied to pods which don't exist any more. We've released the affinity, so clean up
		// any allocations which may still be laying around.
		for _, a := range allocations {
			if err = c.client.IPAM().ReleaseByHandle(c.ctx, a.handle); err != nil {
				logc.WithError(err).Error("Failed to release IP")
				break
			}
		}
		if err != nil {
			logc.WithError(err).Warning("Couldn't release all IPs, will retry later")
			continue
		}
	}

	return nil
}

func (c *Controller) nodeExists(node string) bool {
	_, err := c.clientset.CoreV1().Nodes().Get(node, v1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			return false
		}
		log.WithError(err).Warn("Failed to query node, assume it exists")
	}
	return true
}

func (c *Controller) podExists(name, ns string) bool {
	_, err := c.clientset.CoreV1().Pods(ns).Get(name, v1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			return false
		}
		log.WithError(err).Warn("Failed to query pod, assume it exists")
	}
	return true
}
