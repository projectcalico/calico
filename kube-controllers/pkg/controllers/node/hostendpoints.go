// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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
	"context"
	"fmt"
	"reflect"
	"time"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"

	"github.com/projectcalico/calico/kube-controllers/pkg/config"
	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
)

func NewAutoHEPController(c config.NodeControllerConfig, client client.Interface) *autoHostEndpointController {
	ctrl := &autoHostEndpointController{
		rl:        workqueue.DefaultControllerRateLimiter(),
		config:    c,
		client:    client,
		nodeCache: make(map[string]*libapi.Node),
	}
	return ctrl
}

type autoHostEndpointController struct {
	rl         workqueue.RateLimiter
	config     config.NodeControllerConfig
	client     client.Interface
	nodeCache  map[string]*libapi.Node
	syncStatus bapi.SyncStatus
}

func (c *autoHostEndpointController) RegisterWith(f *DataFeed) {
	// We want nodes, which are sent with key model.ResourceKey
	f.RegisterForNotification(model.ResourceKey{}, c.onUpdate)
	f.RegisterForSyncStatus(c.onStatusUpdate)
}

func (c *autoHostEndpointController) onStatusUpdate(s bapi.SyncStatus) {
	c.syncStatus = s
	switch s {
	case bapi.InSync:
		err := c.syncAllAutoHostendpoints(context.Background())
		if err != nil {
			logrus.WithError(err).Fatal("failed to sync all auto hostendpoints")
		}
	}
}

func (c *autoHostEndpointController) onUpdate(update bapi.Update) {
	// Use the presence / absence of the update Value to determine if this is a delete or not.
	// The value can be nil even if the UpdateType is New or Updated if it is the result of a
	// failed validation in the syncer, and we want to treat those as deletes.
	if update.Value != nil {
		switch update.KVPair.Value.(type) {
		case *libapi.Node:
			n := update.KVPair.Value.(*libapi.Node)
			if c.config.AutoHostEndpoints {
				// Cache all updated nodes.
				c.nodeCache[n.Name] = n

				// If we're already in-sync, sync the node's auto hostendpoint.
				if c.syncStatus == bapi.InSync {
					err := c.syncAutoHostendpointWithRetries(context.Background(), n)
					if err != nil {
						logrus.WithError(err).Fatal()
					}
				}
			}
		default:
			logrus.Warnf("Unexpected kind received over syncer: %s", update.KVPair.Key)
		}
	} else {
		switch update.KVPair.Key.(type) {
		case model.ResourceKey:
			switch update.KVPair.Key.(model.ResourceKey).Kind {
			case libapi.KindNode:
				// Try to perform unmapping based on resource name (calico node name).
				nodeName := update.KVPair.Key.(model.ResourceKey).Name
				if c.config.AutoHostEndpoints && c.syncStatus == bapi.InSync {
					hepName := c.generateAutoHostendpointName(nodeName)
					err := c.deleteHostendpointWithRetries(context.Background(), hepName)
					if err != nil {
						logrus.WithError(err).Fatal()
					}
				}
			default:
				logrus.Warnf("Unexpected kind received over syncer: %s", update.KVPair.Key)
			}
		}
	}
}

// deleteAutoHostendpointsWithoutNodes deletes auto hostendpoints that either
// reference a Calico node that doesn't exist, or, that remain after
// autoHostEndpoints has been disabled.
func (c *autoHostEndpointController) deleteAutoHostendpointsWithoutNodes(ctx context.Context, heps map[string]api.HostEndpoint) error {
	for _, hep := range heps {
		_, hepNodeExists := c.nodeCache[hep.Spec.Node]

		if !hepNodeExists || !c.config.AutoHostEndpoints {
			err := c.deleteHostendpoint(ctx, hep.Name)
			if err != nil {
				log.WithError(err).Warnf("failed to delete hostendpoint %q", hep.Name)
				return err
			}
		}
	}
	return nil
}

// createUpdateAutohostendpoints creates or updates all auto hostendpoints.
func (c *autoHostEndpointController) createUpdateAutohostendpoints(ctx context.Context) error {
	for _, node := range c.nodeCache {
		err := c.syncAutoHostendpoint(ctx, node)
		if err != nil {
			log.WithError(err).Warnf("failed to sync hostendpoint for node %q", node.Name)
			return err
		}
	}
	return nil
}

// syncAllAutoHostendpoints ensures that the expected auto hostendpoints exist,
func (c *autoHostEndpointController) syncAllAutoHostendpoints(ctx context.Context) error {
	for n := 1; n <= 5; n++ {
		log.Debugf("syncing all hostendpoints. attempt #%v", n)
		autoHeps, err := c.listAutoHostendpoints(ctx)
		if err != nil {
			log.WithError(err).Warn("failed to list hostendpoints")
			time.Sleep(retrySleepTime)
			continue
		}

		// Delete any dangling auto hostendpoints
		if err := c.deleteAutoHostendpointsWithoutNodes(ctx, autoHeps); err != nil {
			log.WithError(err).Warn("failed to delete dangling hostendpoints")
			time.Sleep(retrySleepTime)
			continue
		}

		// For every Calico node in our cache, create/update the auto hostendpoint
		// for it.
		if c.config.AutoHostEndpoints {
			if err := c.createUpdateAutohostendpoints(ctx); err != nil {
				log.WithError(err).Warn("failed to sync hostendpoint for nodes")
				time.Sleep(retrySleepTime)
				continue
			}
		}

		log.Info("successfully synced all hostendpoints")
		return nil
	}
	return fmt.Errorf("too many retries when syncing all hostendpoints")
}

// syncAutoHostendpoint syncs the auto hostendpoint for the given node.
func (c *autoHostEndpointController) syncAutoHostendpoint(ctx context.Context, node *libapi.Node) error {
	hepName := c.generateAutoHostendpointName(node.Name)
	log.Debugf("syncing hostendpoint %q from node %+v", hepName, node)

	// Try getting the host endpoint.
	expectedHep := c.generateAutoHostendpointFromNode(node)
	currentHep, err := c.client.HostEndpoints().Get(ctx, hepName, options.GetOptions{})
	if err != nil {
		switch err.(type) {
		case errors.ErrorResourceDoesNotExist:
			if _, err := c.createAutoHostendpoint(ctx, node); err != nil {
				return err
			}
		default:
			return err
		}
	} else if err := c.updateHostendpoint(currentHep, expectedHep); err != nil {
		return err
	}

	log.WithField("hep.Name", expectedHep.Name).Debug("successfully synced hostendpoint")
	return nil
}

// syncAutoHostendpointWithRetries syncs the auto hostendpoint for the given
// node, retrying a few times if needed.
func (c *autoHostEndpointController) syncAutoHostendpointWithRetries(ctx context.Context, node *libapi.Node) error {
	for n := 1; n <= 5; n++ {
		log.Debugf("syncing hostendpoint for node %q. attempt #%v", node.Name, n)
		if err := c.syncAutoHostendpoint(ctx, node); err != nil {
			log.WithError(err).Infof("failed to sync host endpoint for node %q, retrying", node.Name)
			time.Sleep(retrySleepTime)
			continue
		}
		return nil
	}
	return fmt.Errorf("too many retries when syncing hostendpoint for node %q", node.Name)
}

// listAutoHostendpoints returns a map of auto hostendpoints keyed by the
// hostendpoint's name.
func (c *autoHostEndpointController) listAutoHostendpoints(ctx context.Context) (map[string]api.HostEndpoint, error) {
	time.Sleep(c.rl.When(RateLimitCalicoList))
	heps, err := c.client.HostEndpoints().List(ctx, options.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("could not list hostendpoints: %v", err.Error())
	}
	c.rl.Forget(RateLimitCalicoList)
	m := make(map[string]api.HostEndpoint)
	for _, h := range heps.Items {
		if isAutoHostendpoint(&h) {
			m[h.Name] = h
		}
	}
	return m, nil
}

// deleteHostendpoint removes the specified hostendpoint, optionally retrying
// the operation a few times until it succeeds.
func (c *autoHostEndpointController) deleteHostendpoint(ctx context.Context, hepName string) error {
	log.Debugf("deleting hostendpoint %q", hepName)
	time.Sleep(c.rl.When(RateLimitCalicoDelete))
	_, err := c.client.HostEndpoints().Delete(ctx, hepName, options.DeleteOptions{})
	if err != nil {
		log.WithError(err).Warnf("could not delete host endpoint %q", hepName)
		return err
	}
	c.rl.Forget(RateLimitCalicoDelete)

	log.Infof("deleted hostendpoint %q", hepName)
	return nil
}

func (c *autoHostEndpointController) deleteHostendpointWithRetries(ctx context.Context, hepName string) error {
	for n := 1; n <= 5; n++ {
		log.Debugf("deleting hostendpoint %q. attempt #%v", hepName, n)
		if err := c.deleteHostendpoint(ctx, hepName); err != nil {
			switch err.(type) {
			case errors.ErrorResourceDoesNotExist:
				log.Infof("did not delete hostendpoint %q because it doesn't exist", hepName)
				return nil
			default:
				log.WithError(err).Infof("failed to delete host endpoint %q, retrying", hepName)
				time.Sleep(retrySleepTime)
				continue
			}
		}
		return nil
	}
	return fmt.Errorf("too many retries when deleting hostendpoint %q", hepName)
}

// isAutoHostendpoint determines if the given hostendpoint is managed by
// kube-controllers.
func isAutoHostendpoint(h *api.HostEndpoint) bool {
	v, ok := h.Labels[hepCreatedLabelKey]
	return ok && v == hepCreatedLabelValue
}

// createAutoHostendpoint creates an auto hostendpoint for the specified node.
func (c *autoHostEndpointController) createAutoHostendpoint(ctx context.Context, n *libapi.Node) (*api.HostEndpoint, error) {
	hep := c.generateAutoHostendpointFromNode(n)

	time.Sleep(c.rl.When(RateLimitCalicoCreate))
	res, err := c.client.HostEndpoints().Create(ctx, hep, options.SetOptions{})
	if err != nil {
		log.Warnf("could not create hostendpoint for node: %v", err)
		return nil, err
	}
	c.rl.Forget(RateLimitCalicoCreate)
	return res, nil
}

// generateAutoHostendpointName returns the auto hostendpoint's name.
func (c *autoHostEndpointController) generateAutoHostendpointName(nodeName string) string {
	return fmt.Sprintf("%s-auto-hep", nodeName)
}

// getAutoHostendpointExpectedIPs returns all of the known IPs on the node resource
// that should set on the auto hostendpoint.
func (c *autoHostEndpointController) getAutoHostendpointExpectedIPs(node *libapi.Node) []string {
	expectedIPs := []string{}
	ipMap := make(map[string]struct{}) // used to avoid adding duplicates to expectedIPs
	if node.Spec.BGP != nil {
		// BGP IPv4 and IPv6 addresses are CIDRs.
		if node.Spec.BGP.IPv4Address != "" {
			ip, _, _ := net.ParseCIDROrIP(node.Spec.BGP.IPv4Address)
			expectedIPs = append(expectedIPs, ip.String())
			ipMap[ip.String()] = struct{}{}
		}
		if node.Spec.BGP.IPv6Address != "" {
			ip, _, _ := net.ParseCIDROrIP(node.Spec.BGP.IPv6Address)
			expectedIPs = append(expectedIPs, ip.String())
			ipMap[ip.String()] = struct{}{}
		}
		if node.Spec.BGP.IPv4IPIPTunnelAddr != "" {
			expectedIPs = append(expectedIPs, node.Spec.BGP.IPv4IPIPTunnelAddr)
			ipMap[node.Spec.BGP.IPv4IPIPTunnelAddr] = struct{}{}
		}
	}
	if node.Spec.IPv4VXLANTunnelAddr != "" {
		expectedIPs = append(expectedIPs, node.Spec.IPv4VXLANTunnelAddr)
		ipMap[node.Spec.IPv4VXLANTunnelAddr] = struct{}{}
	}
	if node.Spec.IPv6VXLANTunnelAddr != "" {
		expectedIPs = append(expectedIPs, node.Spec.IPv6VXLANTunnelAddr)
		ipMap[node.Spec.IPv6VXLANTunnelAddr] = struct{}{}
	}
	if node.Spec.Wireguard != nil && node.Spec.Wireguard.InterfaceIPv4Address != "" {
		expectedIPs = append(expectedIPs, node.Spec.Wireguard.InterfaceIPv4Address)
		ipMap[node.Spec.Wireguard.InterfaceIPv4Address] = struct{}{}
	}
	for _, addr := range node.Spec.Addresses {
		// Add internal IPs only
		if addr.Type == libapi.InternalIP {
			if _, ok := ipMap[addr.Address]; !ok {
				expectedIPs = append(expectedIPs, addr.Address)
			}
		}
	}
	return expectedIPs
}

// generateAutoHostendpointFromNode returns the expected auto hostendpoint to be
// created from the given node.
func (c *autoHostEndpointController) generateAutoHostendpointFromNode(node *libapi.Node) *api.HostEndpoint {
	hepLabels := make(map[string]string, len(node.Labels)+1)
	for k, v := range node.Labels {
		hepLabels[k] = v
	}
	hepLabels[hepCreatedLabelKey] = hepCreatedLabelValue

	return &api.HostEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:   c.generateAutoHostendpointName(node.Name),
			Labels: hepLabels,
		},
		Spec: api.HostEndpointSpec{
			Node:          node.Name,
			InterfaceName: "*",
			ExpectedIPs:   c.getAutoHostendpointExpectedIPs(node),
			Profiles:      []string{resources.DefaultAllowProfileName},
		},
	}
}

// hostendpointNeedsUpdate returns true if the current automatic hostendpoint
// needs to be updated.
func (c *autoHostEndpointController) hostendpointNeedsUpdate(current *api.HostEndpoint, expected *api.HostEndpoint) bool {
	log.Debugf("checking if hostendpoint needs update\ncurrent: %#v\nexpected: %#v", current, expected)
	if !reflect.DeepEqual(current.Labels, expected.Labels) {
		log.WithField("hep.Name", current.Name).Debug("hostendpoint needs update because of labels")
		return true
	}
	if !reflect.DeepEqual(current.Spec.ExpectedIPs, expected.Spec.ExpectedIPs) {
		log.WithField("hep.Name", current.Name).Debug("hostendpoint needs update because of expectedIPs")
		return true
	}
	if current.Spec.InterfaceName != expected.Spec.InterfaceName {
		log.WithField("hep.Name", current.Name).Debug("hostendpoint needs update because of interfaceName")
		return true
	}
	log.WithField("hep.Name", current.Name).Debug("hostendpoint does not need update")
	return false
}

// updateHostendpoint updates the current hostendpoint so that it matches the
// expected hostendpoint.
func (c *autoHostEndpointController) updateHostendpoint(current *api.HostEndpoint, expected *api.HostEndpoint) error {
	if c.hostendpointNeedsUpdate(current, expected) {
		log.WithField("hep.Name", current.Name).Debug("hostendpoint needs update")
		expected.ResourceVersion = current.ResourceVersion
		expected.ObjectMeta.CreationTimestamp = current.ObjectMeta.CreationTimestamp
		expected.ObjectMeta.UID = current.ObjectMeta.UID

		time.Sleep(c.rl.When(RateLimitCalicoUpdate))
		_, err := c.client.HostEndpoints().Update(context.Background(), expected, options.SetOptions{})
		if err == nil {
			c.rl.Forget(RateLimitCalicoUpdate)
		}
		return err
	}
	log.WithField("hep.Name", current.Name).Debug("hostendpoint not updated")
	return nil
}
