// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.
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
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/projectcalico/calico/kube-controllers/pkg/config"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/utils"
	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
)

const (
	hostEndpointNameSuffix       = "auto-hep"
	defaultHostEndpointInterface = "*"
)

type hostEndpointTracker struct {
	hostEndpointsByNode map[string]map[string]*api.HostEndpoint
}

func (t *hostEndpointTracker) addHostEndpoint(hostEndpoint *api.HostEndpoint) {
	if t.hostEndpointsByNode[hostEndpoint.Spec.Node] == nil {
		t.hostEndpointsByNode[hostEndpoint.Spec.Node] = make(map[string]*api.HostEndpoint)
	}
	t.hostEndpointsByNode[hostEndpoint.Spec.Node][hostEndpoint.Name] = hostEndpoint
}

func (t *hostEndpointTracker) deleteHostEndpoint(hostEndpointName string) {
	var nodeName string
	for _, heps := range t.hostEndpointsByNode {
		for hepName, hep := range heps {
			if hepName == hostEndpointName {
				nodeName = hep.Spec.Node
				delete(t.hostEndpointsByNode[hep.Spec.Node], hepName)
			}
		}
	}

	if len(t.hostEndpointsByNode[nodeName]) == 0 {
		delete(t.hostEndpointsByNode, nodeName)
	}
}

func (t *hostEndpointTracker) getHostEndpoint(hostEndpointName string) *api.HostEndpoint {
	for _, heps := range t.hostEndpointsByNode {
		for hepName, hep := range heps {
			if hepName == hostEndpointName {
				return hep
			}
		}
	}

	return nil
}

func (t *hostEndpointTracker) getHostEndpointsForNode(nodeName string) []*api.HostEndpoint {
	var hostEndpoints []*api.HostEndpoint
	for _, hep := range t.hostEndpointsByNode[nodeName] {
		hostEndpoints = append(hostEndpoints, hep)
	}

	return hostEndpoints
}

func (t *hostEndpointTracker) getAllHostEndpoints() []*api.HostEndpoint {
	var hostEndpoints []*api.HostEndpoint
	for _, heps := range t.hostEndpointsByNode {
		for _, hep := range heps {
			hostEndpoints = append(hostEndpoints, hep)
		}
	}

	return hostEndpoints
}

func NewAutoHEPController(cfg config.NodeControllerConfig, client client.Interface) *autoHostEndpointController {
	return &autoHostEndpointController{
		config:         cfg,
		client:         client,
		nodeCache:      make(map[string]*libapi.Node),
		nodeUpdates:    make(chan string, utils.BatchUpdateSize),
		syncerUpdates:  make(chan interface{}, utils.BatchUpdateSize),
		syncChan:       make(chan interface{}, 1),
		autoHEPTracker: hostEndpointTracker{hostEndpointsByNode: make(map[string]map[string]*api.HostEndpoint)},
	}
}

type autoHostEndpointController struct {
	config         config.NodeControllerConfig
	client         client.Interface
	syncStatus     bapi.SyncStatus
	nodeCache      map[string]*libapi.Node
	nodeUpdates    chan string
	syncerUpdates  chan interface{}
	syncChan       chan interface{}
	autoHEPTracker hostEndpointTracker
}

func (c *autoHostEndpointController) Start(stop chan struct{}) {
	go c.acceptScheduledRequests(stop)
}

func (c *autoHostEndpointController) RegisterWith(f *utils.DataFeed) {
	// We want nodes and HostEndpoints, which are sent with key model.ResourceKey
	f.RegisterForNotification(model.ResourceKey{}, c.onUpdate)
	f.RegisterForSyncStatus(c.onStatusUpdate)
}

func (c *autoHostEndpointController) onStatusUpdate(s bapi.SyncStatus) {
	c.syncerUpdates <- s
}

func (c *autoHostEndpointController) acceptScheduledRequests(stopCh <-chan struct{}) {
	logrus.Infof("Will run periodic HostEndpoint sync every %s", timer)
	t := time.NewTicker(timer)
	for {
		select {
		case update := <-c.syncerUpdates:
			c.handleUpdate(update)
		case <-t.C:
			logrus.Info("Running periodic HostEndpoint sync")
			c.syncHostEndpoints()
		case <-c.syncChan:
			c.syncHostEndpoints()
		case nodeName := <-c.nodeUpdates:
			logEntry := logrus.WithFields(logrus.Fields{"controller": "HostEndpoint", "type": "nodeUpdate"})
			utils.ProcessBatch(c.nodeUpdates, nodeName, c.syncHostEndpointsForNode, logEntry)
		case <-stopCh:
			return
		}
	}
}

func (c *autoHostEndpointController) onUpdate(update bapi.Update) {
	switch update.Key.(type) {
	case model.ResourceKey:
		switch update.KVPair.Key.(model.ResourceKey).Kind {
		case libapi.KindNode, api.KindHostEndpoint:
			c.syncerUpdates <- update.KVPair
		}
	}
}

func (c *autoHostEndpointController) handleUpdate(update interface{}) {
	switch update := update.(type) {
	case bapi.SyncStatus:
		c.syncStatus = update
		switch update {
		case bapi.InSync:
			logrus.WithField("status", update).Info("Syncer is InSync, kicking sync channel")
			kick(c.syncChan)
		}
	case model.KVPair:
		switch update.Key.(model.ResourceKey).Kind {
		case libapi.KindNode:
			c.handleNodeUpdate(update)
		case api.KindHostEndpoint:
			c.handleHostEndpointUpdate(update)
		}
	}
}

// handleNodeUpdate handles node updates received via the syncer.
// On delete and update we want to trigger hostEndpointSync for this node
func (c *autoHostEndpointController) handleNodeUpdate(kvp model.KVPair) {
	nodeName := kvp.Key.(model.ResourceKey).Name
	if kvp.Value == nil {
		// Node deleted, we want to remove all auto HostEndpoints associated with this node
		delete(c.nodeCache, nodeName)
	} else {
		node := kvp.Value.(*libapi.Node)
		c.nodeCache[node.Name] = node
	}

	if c.syncStatus == bapi.InSync {
		c.nodeUpdates <- nodeName
	}
}

// handleHostEndpointUpdate handles HostEndpoint updates received via syncer.
// We want to delete HostEndpoints that no longer exists, and add/update Auto-HostEndpoints to our local cache
func (c *autoHostEndpointController) handleHostEndpointUpdate(kvp model.KVPair) {
	if kvp.Value == nil {
		hostEndpoint := c.autoHEPTracker.getHostEndpoint(kvp.Key.(model.ResourceKey).Name)
		if hostEndpoint != nil && c.syncStatus == bapi.InSync {
			// If we receive delete and the host endpoint is still in our cache it's possible that the HostEndpoint has been deleted by someone other than our kube-controller
			// we delete the HostEndpoint from our cache and trigger a sync on the node to make sure we're up to date
			c.autoHEPTracker.deleteHostEndpoint(kvp.Key.(model.ResourceKey).Name)
			c.nodeUpdates <- hostEndpoint.Spec.Node
			return
		}
		c.autoHEPTracker.deleteHostEndpoint(kvp.Key.(model.ResourceKey).Name)
		return
	}

	hostEndpoint := kvp.Value.(*api.HostEndpoint)

	if isAutoHostEndpoint(hostEndpoint) {
		if c.syncStatus == bapi.InSync {
			cachedHostEndpoint := c.autoHEPTracker.getHostEndpoint(hostEndpoint.Name)
			if cachedHostEndpoint != nil && c.hostEndpointNeedsUpdate(cachedHostEndpoint, hostEndpoint) {
				// autoHEPTracker is updated during each create and update, we expect the HostEndpoint received via the syncer to be identical to what we have stored
				// If they are different it's possible it's been updated by something other than our kube-controller, we trigger the sync of HostEndpoints for the Node that the HostEndpoint belongs to
				c.autoHEPTracker.addHostEndpoint(hostEndpoint)
				c.nodeUpdates <- hostEndpoint.Spec.Node
				return
			}
		}

		c.autoHEPTracker.addHostEndpoint(hostEndpoint)
	}
}

// syncHostEndpoints() is the main function that is responsible for keeping HostEndpoints in sync for nodes. It does the following:
// 1. Checks if the hostEndpoint controller is disabled, in that case we should delete all previously created HostEndpoints
// 2. Clean up any HostEndpoints that are lingering after a node was deleted
// 3. Go through each node and sync HostEndpoints for that node
func (c *autoHostEndpointController) syncHostEndpoints() {
	if c.syncStatus != bapi.InSync {
		return
	}

	logrus.Infof("Syncing all HostEndpoints")

	if !c.config.AutoHostEndpointConfig.AutoCreate {
		// Create host endpoints is disabled, we need to delete all hostEndpoints that might still be left over after being created by this controller
		for _, hep := range c.autoHEPTracker.getAllHostEndpoints() {
			err := c.deleteHostEndpoint(hep.Name)
			if err != nil {
				logrus.WithError(err).Error("failed to delete host endpoint")
			}
		}

		// We can skip to the rest, all hostEndpoints are deleted and we don't want to generate any new ones
		return
	}

	for nodeName := range c.autoHEPTracker.hostEndpointsByNode {
		if _, ok := c.nodeCache[nodeName]; !ok {
			c.deleteHostEndpointsForNode(nodeName)
		}
	}

	for _, node := range c.nodeCache {
		c.syncHostEndpointsForNode(node.Name)
	}
}

// syncHostEndpointsForNode() sync HostEndpoints for the particular node. It does the following
// 1. If the node was deleted and is no longer in the node cache or AutoCreate is set to Disable, delete all HostEndpoints we have associated with the node
// 2. Create/Sync/Delete the default HostEndpoint based on the createDefaultHostEndpoint option
// 3. Iterate over the Templates and create HostEndpoints for each template that matches the Node by nodeSelector
// 4. Check that there are no extra HostEndpoints we created before that no longer match the kubecontrollersconfiguration or the template, we delete those HostEndpoints
func (c *autoHostEndpointController) syncHostEndpointsForNode(nodeName string) {
	node := c.nodeCache[nodeName]
	if node == nil || !c.config.AutoHostEndpointConfig.AutoCreate {
		// Node has been deleted clean up all HostEndpoints associated with this node
		// or AutoCreate is Disabled, we only want try to create/update host endpoints if AutoCreate is enabled, if any host endpoints are already created for this node they will be deleted
		c.deleteHostEndpointsForNode(nodeName)
		return
	}

	// We keep a list of hostEndpoints that should be created for this node to determine if any should be removed further down
	hostEndpointsMatchingNode := make(map[string]bool)

	if c.config.AutoHostEndpointConfig.CreateDefaultHostEndpoint == api.DefaultHostEndpointsEnabled {
		// First we check that the default hostEndpoint is deleted/not present if createDefaultHostEndpoint is disabled,
		// if enabled we check that the hostEndpoint is created and up to date
		defaultHostEndpointName, err := generateAutoHostEndpointName(nodeName, "", "")
		if err != nil {
			logrus.WithError(err).Error("failed to generate host endpoint name")
			return
		}
		expectedHostEndpoint := c.generateAutoHostEndpoint(node, nil, defaultHostEndpointName, c.getExpectedIPs(node), defaultHostEndpointInterface)
		// Check if current default host endpoint is up to date. Create it if missing
		c.createOrUpdateHostEndpoint(expectedHostEndpoint)

		hostEndpointsMatchingNode[defaultHostEndpointName] = true
	}

	// We check that all hostEndpoints that match the template are created, we also check that they are up to date.
	for _, template := range c.config.AutoHostEndpointConfig.Templates {
		nodeSelector, err := selector.Parse(template.NodeSelector)
		if err != nil {
			logrus.WithError(err).Errorf("failed to parse node selector, skipping host endpoint creation for %s template", template.GenerateName)
			return
		}

		if nodeSelector.Evaluate(node.Labels) {
			expectedIPs := c.getExpectedIPsMatchingInterfaceCIDRs(node, template)
			if len(expectedIPs) == 0 && template.InterfacePattern == "" {
				// Because we do not specify interfaceName in HostEndpoint, expectedIPs should not be empty.
				// If expectedIPs are empty the HostEndpoint will be invalid, and we should not create it
				// If there is an existing HostEndpoint with this name, it will be deleted further down
				f := logrus.Fields{"template": template.GenerateName, "node": node.Name}
				logrus.WithFields(f).Debug("template InterfaceCIDRs do not match any Node IPs")

				continue
			}

			if template.InterfacePattern == "" {
				// When interfacePattern is empty this template will always generate at most one AutoHostEndpoint
				hostEndpointName, err := generateAutoHostEndpointName(node.Name, template.GenerateName, "")
				if err != nil {
					logrus.WithError(err).Error("failed to generate host endpoint name")
					return
				}
				expectedHostEndpoint := c.generateAutoHostEndpoint(node, template.Labels, hostEndpointName, expectedIPs, "")
				c.createOrUpdateHostEndpoint(expectedHostEndpoint)

				hostEndpointsMatchingNode[hostEndpointName] = true

				// If there is no InterfacePattern we only create one host endpoint, we can continue to the next template
				continue
			}

			for _, iface := range node.Spec.Interfaces {
				// If we reached here we know the template has interfacePattern specified, we want to create a HostEndpoint for each interface that matches the regex selector.
				if regexp.MustCompile(template.InterfacePattern).MatchString(iface.Name) {
					// Generate Host Endpoint for interface matching the InterfacePattern from the template
					hostEndpointName, err := generateAutoHostEndpointName(node.Name, template.GenerateName, iface.Name)
					if err != nil {
						logrus.WithError(err).Error("failed to generate host endpoint name")
						return
					}

					// Update the expected IPs with IPs belonging to the matched interface, we do not need to check if it's empty as the generated host endpoint will contain interface name
					expectedIPsWithInterfaceIPs := c.mergeExpectedIPsWithInterfaceIPs(expectedIPs, iface)
					expectedHostEndpoint := c.generateAutoHostEndpoint(node, template.Labels, hostEndpointName, expectedIPsWithInterfaceIPs, iface.Name)
					c.createOrUpdateHostEndpoint(expectedHostEndpoint)

					hostEndpointsMatchingNode[hostEndpointName] = true
				}
			}
		}
	}

	// Check that there are no lingering hostEndpoints that no longer match the template spec for this node
	// We want to delete all HostEndpoints in our HostEndpointTracker that are not part of hostEndpointsMatchingNode
	for _, hostEndpoint := range c.autoHEPTracker.getHostEndpointsForNode(node.Name) {
		if _, ok := hostEndpointsMatchingNode[hostEndpoint.Name]; !ok {
			logrus.Infof("hostEndpoint %s no longer matches template", hostEndpoint.Name)
			err := c.deleteHostEndpoint(hostEndpoint.Name)
			if err != nil {
				logrus.WithError(err).Error("failed to delete host endpoint")
			}
		}
	}
}

// deleteHostEndpointsForNode removes all HostEndpoints associated with the Node
func (c *autoHostEndpointController) deleteHostEndpointsForNode(nodeName string) {
	for _, hep := range c.autoHEPTracker.getHostEndpointsForNode(nodeName) {
		err := c.deleteHostEndpoint(hep.Name)
		if err != nil {
			logrus.WithError(err).Error("failed to delete host endpoint")
			break
		}
	}
}

// deleteHostEndpoint removes the specified HostEndpoint
func (c *autoHostEndpointController) deleteHostEndpoint(hepName string) error {
	logrus.Debugf("deleting hostendpoint %q", hepName)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := c.client.HostEndpoints().Delete(ctx, hepName, options.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return err
	}

	c.autoHEPTracker.deleteHostEndpoint(hepName)
	logrus.WithField("hep.Name", hepName).Debug("deleted hostendpoint")
	return nil
}

// isAutoHostEndpoint determines if the given HostEndpoint is managed by
// kube-controllers.
func isAutoHostEndpoint(h *api.HostEndpoint) bool {
	v, ok := h.Labels[hepCreatedLabelKey]
	return ok && v == hepCreatedLabelValue
}

// generateAutoHostEndpointName generated the name based on the supplied parameters, creating unique name for each HostEndpoint
func generateAutoHostEndpointName(nodeName string, templateName string, interfaceName string) (string, error) {
	if templateName == "" && interfaceName == "" {
		// Default HostEndpoint name
		return hashNameIfTooLong(fmt.Sprintf("%s-%s", nodeName, hostEndpointNameSuffix))
	}

	if templateName != "" && interfaceName == "" {
		// Template HostEndpoint name
		return hashNameIfTooLong(fmt.Sprintf("%s-%s-%s", nodeName, templateName, hostEndpointNameSuffix))
	}

	if templateName != "" && interfaceName != "" {
		// Template HostEndpoint with interfaceName name
		return hashNameIfTooLong(fmt.Sprintf("%s-%s-%s-%s", nodeName, templateName, interfaceName, hostEndpointNameSuffix))
	}

	return "", fmt.Errorf("insufficient HostEndpoint identifiers supplied")
}

// hashNameIfTooLong ensures the given name does not exceed the DNS1123 (253 characters) subdomain length limit.
// If the name is too long, it generates a hash-based name that fits the limit.
func hashNameIfTooLong(name string) (string, error) {
	if len(name) <= validation.DNS1123SubdomainMaxLength {
		return name, nil
	}

	hasher := sha256.New()
	_, err := hasher.Write([]byte(name))
	if err != nil {
		logrus.WithError(err).Error("Failed to generate hash from name")
		return "", err
	}

	hash := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))
	regex := regexp.MustCompile("([-_.])")
	hash = regex.ReplaceAllString(hash, "")
	name = strings.ToLower(fmt.Sprintf("%s-%s", hash, hostEndpointNameSuffix))
	if len(name) > validation.DNS1123SubdomainMaxLength {
		name = name[:validation.DNS1123SubdomainMaxLength]
	}
	return name, nil
}

// mergeExpectedIPsWithInterfaceIPs merges the provided expected IPs with the IP addresses
// found on the specified interface of the given node.
func (c *autoHostEndpointController) mergeExpectedIPsWithInterfaceIPs(expectedIPs []string, iface libapi.NodeInterface) []string {
	for _, addr := range iface.Addresses {
		if !slices.Contains(expectedIPs, addr) {
			expectedIPs = append(expectedIPs, addr)
		}
	}

	return expectedIPs
}

// getExpectedIPsMatchingInterfaceCIDRs finds the matching node IPs to the CIDRs specified in the template
func (c *autoHostEndpointController) getExpectedIPsMatchingInterfaceCIDRs(node *libapi.Node, template config.AutoHostEndpointTemplate) []string {
	filteredExpectedIPs := []string{}
	expectedIPs := c.getExpectedIPs(node)

	for _, ipAddrs := range expectedIPs {
		ip := net.ParseIP(ipAddrs)
		for _, interfaceSelectorCIDR := range template.InterfaceCIDRs {
			_, cidr, err := net.ParseCIDR(string(interfaceSelectorCIDR))
			if err != nil {
				logrus.WithError(err).Errorf("failed to parse interface selector cidr %s", interfaceSelectorCIDR)
				return nil
			}

			if cidr.Contains(ip) {
				filteredExpectedIPs = append(filteredExpectedIPs, ip.String())
				break
			}
		}
	}

	return filteredExpectedIPs
}

// getExpectedIPs returns all the known IPs on the node resource
func (c *autoHostEndpointController) getExpectedIPs(node *libapi.Node) []string {
	expectedIPs := []string{}
	ipMap := make(map[string]struct{}) // used to avoid adding duplicates to expectedIPs
	if node.Spec.BGP != nil {
		// BGP IPv4 and IPv6 addresses are CIDRs.
		if node.Spec.BGP.IPv4Address != "" {
			ip, _, _ := cnet.ParseCIDROrIP(node.Spec.BGP.IPv4Address)
			expectedIPs = append(expectedIPs, ip.String())
			ipMap[ip.String()] = struct{}{}
		}
		if node.Spec.BGP.IPv6Address != "" {
			ip, _, _ := cnet.ParseCIDROrIP(node.Spec.BGP.IPv6Address)
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
	if node.Spec.Wireguard != nil && node.Spec.Wireguard.InterfaceIPv6Address != "" {
		expectedIPs = append(expectedIPs, node.Spec.Wireguard.InterfaceIPv6Address)
		ipMap[node.Spec.Wireguard.InterfaceIPv6Address] = struct{}{}
	}
	for _, addr := range node.Spec.Addresses {
		// Add internal IPs only
		if addr.Type == libapi.InternalIP {
			if _, ok := ipMap[addr.Address]; !ok {
				ipMap[addr.Address] = struct{}{}
				expectedIPs = append(expectedIPs, addr.Address)
			}
		}
	}

	for _, iface := range node.Spec.Interfaces {
		for _, addr := range iface.Addresses {
			if _, ok := ipMap[addr]; !ok {
				ipMap[addr] = struct{}{}
				expectedIPs = append(expectedIPs, addr)
			}
		}
	}

	// Validate that IP address is valid, if we find invalid IP address we remove it from the list and only create autoHEP containing the valid IPs
	var validatedIPs []string
	for _, ip := range expectedIPs {
		parsedIP, _, err := cnet.ParseCIDROrIP(ip)
		if err != nil || parsedIP.IP == nil {
			logrus.WithError(err).Errorf("failed to parse ip %s, removing from expectedIPs", ip)
			continue
		}
		validatedIPs = append(validatedIPs, ip)
	}

	return validatedIPs
}

// generateAutoHostEndpoint returns a HostEndpoint created based on the specific parameters
func (c *autoHostEndpointController) generateAutoHostEndpoint(node *libapi.Node, templateLabels map[string]string, hepName string, expectedIPs []string, interfaceName string) *api.HostEndpoint {
	hepLabels := make(map[string]string)
	for k, v := range node.Labels {
		hepLabels[k] = v
	}
	for k, v := range templateLabels {
		if _, ok := hepLabels[k]; ok {
			f := logrus.Fields{"key": k, "nodeVal": hepLabels[k], "userVal": v}
			logrus.WithFields(f).Warn("overwriting label from underlying Node resource")
		}
		hepLabels[k] = v
	}
	hepLabels[hepCreatedLabelKey] = hepCreatedLabelValue

	hostEndpoint := &api.HostEndpoint{
		TypeMeta: metav1.TypeMeta{
			Kind: api.KindHostEndpoint,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:   hepName,
			Labels: hepLabels,
		},
		Spec: api.HostEndpointSpec{
			Node:          node.Name,
			ExpectedIPs:   expectedIPs,
			Profiles:      []string{resources.DefaultAllowProfileName},
			InterfaceName: interfaceName,
		},
	}

	return hostEndpoint
}

// hostEndpointNeedsUpdate returns true if the current automatic HostEndpoint
// needs to be updated.
func (c *autoHostEndpointController) hostEndpointNeedsUpdate(current *api.HostEndpoint, expected *api.HostEndpoint) bool {
	logrus.Debugf("checking if hostendpoint needs update\ncurrent: %#v\nexpected: %#v", current, expected)
	if !reflect.DeepEqual(current.Labels, expected.Labels) {
		logrus.WithField("hep.Name", current.Name).Debug("hostendpoint needs update because of labels")
		return true
	}
	if !reflect.DeepEqual(current.Spec.ExpectedIPs, expected.Spec.ExpectedIPs) {
		logrus.WithField("hep.Name", current.Name).Debug("hostendpoint needs update because of expectedIPs")
		return true
	}
	if current.Spec.InterfaceName != expected.Spec.InterfaceName {
		logrus.WithField("hep.Name", current.Name).Debug("hostendpoint needs update because of interfaceName")
		return true
	}
	logrus.WithField("hep.Name", current.Name).Debug("hostendpoint does not need update")
	return false
}

// createOrUpdateHostEndpoint checks if the supplied expected HostEndpoint is currently in our cache and matches.
// If not we either create it, if it's not part of our cache or update it if it's in our cache but out of date
func (c *autoHostEndpointController) createOrUpdateHostEndpoint(expected *api.HostEndpoint) {
	current := c.autoHEPTracker.getHostEndpoint(expected.Name)
	if current == nil {
		if err := c.createAutoHostEndpoint(expected); err != nil {
			logrus.WithError(err).Errorf("failed to create host endpoint %s", expected.Name)
		}
		return
	}
	if err := c.updateHostEndpoint(current, expected); err != nil {
		logrus.WithError(err).Errorf("failed to update host endpoint %s", expected.Name)
	}
}

// createAutoHostEndpoint creates the supplied HostEndpoint
func (c *autoHostEndpointController) createAutoHostEndpoint(hostEndpoint *api.HostEndpoint) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	hostEndpoint, err := c.client.HostEndpoints().Create(ctx, hostEndpoint, options.SetOptions{})
	if err != nil {
		logrus.Warnf("could not create hostendpoint for node: %v", err)
		return err
	}

	logrus.WithField("hep.Name", hostEndpoint.Name).Debug("created hostendpoint")
	c.autoHEPTracker.addHostEndpoint(hostEndpoint)
	return nil
}

// updateHostEndpoint updates the current HostEndpoint so that it matches the expected HostEndpoint.
func (c *autoHostEndpointController) updateHostEndpoint(current *api.HostEndpoint, expected *api.HostEndpoint) error {
	if c.hostEndpointNeedsUpdate(current, expected) {
		logrus.WithField("hep.Name", current.Name).Debug("hostendpoint needs update")

		expected.ResourceVersion = current.ResourceVersion
		expected.CreationTimestamp = current.CreationTimestamp
		expected.UID = current.UID

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		hostEndpoint, err := c.client.HostEndpoints().Update(ctx, expected, options.SetOptions{})
		if err != nil {
			return err
		}

		c.autoHEPTracker.addHostEndpoint(hostEndpoint)
		logrus.WithField("hep.Name", current.Name).Debug("hostendpoint updated")

		return nil
	}
	logrus.WithField("hep.Name", current.Name).Debug("hostendpoint not updated")
	return nil
}
