// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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

package node

import (
	"fmt"
	"strings"
	"time"

	bapi "github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// syncDeleteKDD cleans up any IPAM resources which should no longer exist based on nodes in the cluster.
// It returns an error if it is determined that there are resources which should be cleaned up, but is unable to do so.
// It does not return an error if it is successful, or if there is no action to take.
func (c *NodeController) syncDeleteKDD() error {
	// Get the backend client.
	type accessor interface {
		Backend() bapi.Client
	}
	bc := c.calicoClient.(accessor).Backend()

	// Query all IPAM blocks in the cluster, ratelimiting calls.
	time.Sleep(c.rl.When(RateLimitCalicoList))
	blocks, err := bc.List(c.ctx, model.BlockListOptions{}, "")
	if err != nil {
		return err
	}
	c.rl.Forget(RateLimitCalicoList)

	// Build a list of all the nodes in the cluster based on IPAM allocations across all
	// blocks, plus affinities.
	nodes := map[string][]model.AllocationAttribute{}
	for _, kvp := range blocks.KVPairs {
		b := kvp.Value.(*model.AllocationBlock)

		// Include affinity if it exists. We want to track nodes even
		// if there are no IPs actually assigned to that node.
		if b.Affinity != nil {
			n := strings.TrimLeft(*b.Affinity, "host:")
			if _, ok := nodes[n]; !ok {
				nodes[n] = []model.AllocationAttribute{}
			}
		}

		// Go through each IPAM allocation, check its attributes for the node it is assigned to.
		for _, idx := range b.Allocations {
			if idx == nil {
				// Not allocated.
				continue
			}
			attr := b.Attributes[*idx]

			// Track nodes based on IP allocations.
			if val, ok := attr.AttrSecondary["node"]; ok {
				if _, ok := nodes[val]; !ok {
					nodes[val] = []model.AllocationAttribute{}
				}

				// If there is no handle, then skip this IP. We need the handle
				// in order to release the IP below.
				if attr.AttrPrimary == nil {
					log.Warnf("Skipping IP with no handle")
					continue
				}

				// Add this allocation to the node, so we can release it later if
				// we need to.
				nodes[val] = append(nodes[val], attr)
			}
		}
	}
	log.Debugf("Nodes in IPAM: %v", nodes)

	// For each node present in IPAM, if it doesn't exist in the Kubernetes API then we
	// should consider it a candidate for cleanup.
	for node, allocations := range nodes {
		// Check if it exists in the Kubernetes API.
		logc := log.WithField("node", node)
		if c.nodeExists(node) {
			logc.Debug("Node still exists, continue")
			continue
		}

		// Node exists in IPAM but not in the Kubernetes API. Go through each IP address and
		// check to see if the pod it references exists. If all the pods on that node are gone,
		// continue with deletion. If any pod still exists, we skip this node. We want to be
		// extra sure that the node is gone before we clean it up.
		canDelete := true
		for _, a := range allocations {
			ns := a.AttrSecondary["namespace"]
			pod := a.AttrSecondary["pod"]

			// TODO: Need to handle IPIP addresses somehow. They are allocated in calico-ipam, but
			// currently don't have this metadata attached.
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
			// Return an error here, it will trigger a reschedule of this call.
			logc.Infof("Can't cleanup node yet - pods still exist")
			return fmt.Errorf("Cannot clean up node yet, pods still exist")
		}

		// Potentially ratelimit node cleanup.
		time.Sleep(c.rl.When(RateLimitCalicoDelete))
		logc.Info("Cleaning up IPAM resources for deleted node")
		if err := c.cleanupNode(node, allocations); err != nil {
			// TODO: We might want to clean up other nodes before returning.
			return err
		}
		c.rl.Forget(RateLimitCalicoDelete)
	}

	log.Info("Node and IPAM data is in sync")
	return nil
}

func (c *NodeController) cleanupNode(node string, allocations []model.AllocationAttribute) error {
	// At this point, we've verified that the node isn't in Kubernetes and that all the allocations
	// are tied to pods which don't exist any more. Clean up any allocations which may still be laying around.
	logc := log.WithField("node", node)
	retry := false
	for _, a := range allocations {
		if err := c.calicoClient.IPAM().ReleaseByHandle(c.ctx, *a.AttrPrimary); err != nil {
			if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok {
				// If it doesn't exist, we're OK, since we don't want it to!
				// Try to release any other allocations, but we'll still return an error
				// to retry the whole thing from the top. On the retry,
				// we should no longer see any allocations.
				logc.WithField("handle", *a.AttrPrimary).Debug("IP already released")
				retry = true
				continue
			}
			logc.WithError(err).WithField("handle", *a.AttrPrimary).Warning("Failed to release IP")
			retry = true
			break
		}
	}

	if retry {
		logc.Info("Couldn't release all IPs for stale node, schedule retry")
		return fmt.Errorf("Couldn't release all IPs")
	}

	// Release the affinities for this node, requiring that the blocks are empty.
	if err := c.calicoClient.IPAM().ReleaseHostAffinities(c.ctx, node, true); err != nil {
		logc.WithError(err).Errorf("Failed to release block affinities for node")
		return err
	}
	logc.Debug("Released all affinities for node")

	return nil
}

func (c *NodeController) nodeExists(node string) bool {
	_, err := c.k8sClientset.CoreV1().Nodes().Get(node, v1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			return false
		}
		log.WithError(err).Warn("Failed to query node, assume it exists")
	}
	return true
}

func (c *NodeController) podExists(name, ns string) bool {
	_, err := c.k8sClientset.CoreV1().Pods(ns).Get(name, v1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			return false
		}
		log.WithError(err).Warn("Failed to query pod, assume it exists")
	}
	return true
}
