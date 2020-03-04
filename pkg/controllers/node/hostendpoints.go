// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/options"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// deleteAutoHostendpointsWithoutNodes deletes auto hostendpoints that either
// reference a Calico node that doesn't exist, or, that remain after
// autoHostEndpoints has been disabled.
func (c *NodeController) deleteAutoHostendpointsWithoutNodes(heps map[string]api.HostEndpoint) error {
	for _, hep := range heps {
		_, hepNodeExists := c.nodeCache[hep.Spec.Node]

		if !hepNodeExists || c.config.AutoHostEndpoints != "enabled" {
			err := c.deleteHostendpoint(hep.Name)
			if err != nil {
				log.WithError(err).Warnf("failed to delete hostendpoint %q", hep.Name)
				return err
			}
		}
	}
	return nil
}

// createUpdateAutohostendpoints creates or updates all auto hostendpoints.
func (c *NodeController) createUpdateAutohostendpoints() error {
	for _, node := range c.nodeCache {
		err := c.syncAutoHostendpoint(node)
		if err != nil {
			log.WithError(err).Warnf("failed to sync hostendpoint for node %q", node.Name)
			return err
		}
	}
	return nil
}

// syncAllAutoHostendpoints ensures that the expected auto hostendpoints exist,
func (c *NodeController) syncAllAutoHostendpoints() error {
	for n := 1; n <= 5; n++ {
		log.Debugf("syncing all hostendpoints. attempt #%v", n)
		autoHeps, err := c.listAutoHostendpoints()
		if err != nil {
			log.WithError(err).Warn("failed to list hostendpoints")
			time.Sleep(retrySleepTime)
			continue
		}

		// Delete any dangling auto hostendpoints
		if err := c.deleteAutoHostendpointsWithoutNodes(autoHeps); err != nil {
			log.WithError(err).Warn("failed to delete dangling hostendpoints")
			time.Sleep(retrySleepTime)
			continue
		}

		// For every Calico node in our cache, create/update the auto hostendpoint
		// for it.
		if c.config.AutoHostEndpoints == "enabled" {
			if err := c.createUpdateAutohostendpoints(); err != nil {
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
func (c *NodeController) syncAutoHostendpoint(node *api.Node) error {
	hepName := c.generateAutoHostendpointName(node.Name)
	log.Debugf("syncing hostendpoint %q from node %+v", hepName, node)

	// Try getting the host endpoint.
	expectedHep := c.generateAutoHostendpointFromNode(node)
	currentHep, err := c.calicoClient.HostEndpoints().Get(c.ctx, hepName, options.GetOptions{})
	if err != nil {
		switch err.(type) {
		case errors.ErrorResourceDoesNotExist:
			if _, err := c.createAutoHostendpoint(node); err != nil {
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
func (c *NodeController) syncAutoHostendpointWithRetries(node *api.Node) error {
	for n := 1; n <= 5; n++ {
		log.Debugf("syncing hostendpoint for node %q. attempt #%v", node.Name, n)
		if err := c.syncAutoHostendpoint(node); err != nil {
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
func (c *NodeController) listAutoHostendpoints() (map[string]api.HostEndpoint, error) {
	time.Sleep(c.rl.When(RateLimitCalicoList))
	heps, err := c.calicoClient.HostEndpoints().List(c.ctx, options.ListOptions{})
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
func (c *NodeController) deleteHostendpoint(hepName string) error {
	log.Debugf("deleting hostendpoint %q", hepName)
	time.Sleep(c.rl.When(RateLimitCalicoDelete))
	_, err := c.calicoClient.HostEndpoints().Delete(c.ctx, hepName, options.DeleteOptions{})
	if err != nil {
		log.WithError(err).Warnf("could not delete host endpoint %q", hepName)
		return err
	}
	c.rl.Forget(RateLimitCalicoDelete)

	log.Infof("deleted hostendpoint %q", hepName)
	return nil
}

func (c *NodeController) deleteHostendpointWithRetries(hepName string) error {
	for n := 1; n <= 5; n++ {
		log.Debugf("deleting hostendpoint %q. attempt #%v", hepName, n)
		if err := c.deleteHostendpoint(hepName); err != nil {
			switch err.(type) {
			case errors.ErrorResourceDoesNotExist:
				log.Infof("did not delete hostendpoint %q beacuse it doesn't exist", hepName)
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
func (c *NodeController) createAutoHostendpoint(n *api.Node) (*api.HostEndpoint, error) {
	hep := c.generateAutoHostendpointFromNode(n)

	time.Sleep(c.rl.When(RateLimitCalicoCreate))
	res, err := c.calicoClient.HostEndpoints().Create(c.ctx, hep, options.SetOptions{})
	if err != nil {
		log.Warnf("could not create hostendpoint for node: %v", err)
		return nil, err
	}
	c.rl.Forget(RateLimitCalicoCreate)
	return res, nil
}

// generateAutoHostendpointName returns the auto hostendpoint's name.
func (c *NodeController) generateAutoHostendpointName(nodeName string) string {
	return fmt.Sprintf("%s-auto-hep", nodeName)
}

// getAutoHostendpointExpectedIPs returns all of the known IPs on the node resource
// that should set on the auto hostendpoint.
func (c *NodeController) getAutoHostendpointExpectedIPs(node *api.Node) []string {
	expectedIPs := []string{}
	if node.Spec.BGP != nil {
		// BGP IPv4 and IPv6 addresses are CIDRs.
		if node.Spec.BGP.IPv4Address != "" {
			ip, _, _ := net.ParseCIDROrIP(node.Spec.BGP.IPv4Address)
			expectedIPs = append(expectedIPs, ip.String())
		}
		if node.Spec.BGP.IPv6Address != "" {
			ip, _, _ := net.ParseCIDROrIP(node.Spec.BGP.IPv6Address)
			expectedIPs = append(expectedIPs, ip.String())
		}
		if node.Spec.BGP.IPv4IPIPTunnelAddr != "" {
			expectedIPs = append(expectedIPs, node.Spec.BGP.IPv4IPIPTunnelAddr)
		}
	}
	if node.Spec.IPv4VXLANTunnelAddr != "" {
		expectedIPs = append(expectedIPs, node.Spec.IPv4VXLANTunnelAddr)
	}
	return expectedIPs
}

// generateAutoHostendpointFromNode returns the expected auto hostendpoint to be
// created from the given node.
func (c *NodeController) generateAutoHostendpointFromNode(node *api.Node) *api.HostEndpoint {
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
		},
	}
}

// hostendpointNeedsUpdate returns true if the current automatic hostendpoint
// needs to be updated.
func (c *NodeController) hostendpointNeedsUpdate(current *api.HostEndpoint, expected *api.HostEndpoint) bool {
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
func (c *NodeController) updateHostendpoint(current *api.HostEndpoint, expected *api.HostEndpoint) error {
	if c.hostendpointNeedsUpdate(current, expected) {
		log.WithField("hep.Name", current.Name).Debug("hostendpoint needs update")
		expected.ResourceVersion = current.ResourceVersion
		expected.ObjectMeta.CreationTimestamp = current.ObjectMeta.CreationTimestamp
		expected.ObjectMeta.UID = current.ObjectMeta.UID

		time.Sleep(c.rl.When(RateLimitCalicoUpdate))
		_, err := c.calicoClient.HostEndpoints().Update(context.Background(), expected, options.SetOptions{})
		if err == nil {
			c.rl.Forget(RateLimitCalicoUpdate)
		}
		return err
	}
	log.WithField("hep.Name", current.Name).Debug("hostendpoint not updated")
	return nil
}
