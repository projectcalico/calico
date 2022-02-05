// Copyright (c) 2019,2021 Tigera, Inc. All rights reserved.
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

package flannelmigration

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/projectcalico/calico/libcalico-go/lib/ipam"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

const (
	flannelNodeAnnotationKeyBackendData = "backend-data"
	flannelNodeAnnotationKeyBackendType = "backend-type"
	flannelNodeAnnotationKeyPublicIP    = "public-ip"
	defaultIpv4PoolName                 = "default-ipv4-ippool"
	defaultFelixConfigurationName       = "default"
)

// IPAMMigrator responsible for migrating host-local IPAM to Calico IPAM.
// It also converts Flannel vxlan setup for each hosts to Calico vxlan setup.
// IPAM migration process should be idempotent. It can be restarted and still be able to
// complete the process.
type ipamMigrator struct {
	ctx          context.Context
	calicoClient client.Interface
	k8sClientset *kubernetes.Clientset
	config       *Config
}

func NewIPAMMigrator(ctx context.Context, k8sClientset *kubernetes.Clientset, calicoClient client.Interface, config *Config) ipamMigrator {
	return ipamMigrator{
		ctx:          ctx,
		calicoClient: calicoClient,
		k8sClientset: k8sClientset,
		config:       config,
	}
}

// Initialise IPAM migrator.
// Currently do nothing, no initialization steps needed.
func (m ipamMigrator) Initialise() error {
	return nil
}

// Create and initialise default Calico IPPool if not exists.
// Update default FelixConfiguration with Flannel VNI and vxlan port.
func (m ipamMigrator) InitialiseIPPoolAndFelixConfig() error {
	// Validate config and get pod CIDR.
	_, cidr, err := cnet.ParseCIDR(m.config.FlannelNetwork)
	if err != nil {
		return fmt.Errorf("Failed to parse the CIDR '%s'", m.config.FlannelNetwork)
	}

	// Based on FlannelSubnetLen, work out the size of ippool.
	blockSize := m.config.DefaultIppoolSize
	if m.config.FlannelSubnetLen > m.config.DefaultIppoolSize {
		// Flannel subnet is smaller than one Calico IPAM block with default size of /26.
		blockSize = m.config.FlannelSubnetLen
	}

	// Canal creates default ippool and FelixConfigurations with no VXLAN.
	// In this case, we should not check vxlan settings for existing ippool or FelixConfigurations.
	// Instead, we need to update them to enable vxlan.
	checkVxlan := !m.config.IsRunningCanal()

	// Create default ippool with vxlan enabled
	err = createDefaultVxlanIPPool(m.ctx, m.calicoClient, cidr, blockSize, m.config.FlannelIPMasq, checkVxlan)
	if err != nil {
		return fmt.Errorf("Failed to create default ippool")
	}

	// Update or create default Felix configuration with Flannel VNI and vxlan port.
	err = updateOrCreateDefaultFelixConfiguration(m.ctx, m.calicoClient,
		m.config.FlannelVNI, m.config.FlannelPort, m.config.FlannelMTU,
		checkVxlan)
	if err != nil {
		return fmt.Errorf("Failed to create default ippool")
	}

	return nil
}

// Create Calico IPAM blocks for a Kubernetes node.
func (m ipamMigrator) SetupCalicoIPAMForNode(node *v1.Node) error {
	if node == nil {
		return fmt.Errorf("nil pointer for node")
	}

	// Get podCIDR for node.
	if node.Spec.PodCIDR == "" {
		return fmt.Errorf("node %s pod cidr not assigned", node.Name)
	}

	// Get first IP address which is used by Flannel as vtep IP.
	vtepIP, cidr, err := cnet.ParseCIDR(node.Spec.PodCIDR)
	if err != nil {
		return err
	}

	// Get Flannel vxlan setup from node annotations. An example is
	// flannel.alpha.coreos.com/backend-data: '{"VtepMAC":"56:1d:8d:30:79:97"}'
	// flannel.alpha.coreos.com/backend-type: vxlan
	// flannel.alpha.coreos.com/public-ip: 172.16.101.96
	backendType, ok := node.Annotations[m.config.FlannelAnnotationPrefix+"/"+flannelNodeAnnotationKeyBackendType]
	if !ok {
		return fmt.Errorf("node %s missing annotation for Flannel backend type", node.Name)
	}
	if backendType != "vxlan" {
		return fmt.Errorf("node %s got wrong Flannel backend type %s", node.Name, backendType)
	}

	backendData, ok := node.Annotations[m.config.FlannelAnnotationPrefix+"/"+flannelNodeAnnotationKeyBackendData]
	if !ok {
		return fmt.Errorf("node %s missing annotation for Flannel backend data", node.Name)
	}

	publicIP, ok := node.Annotations[m.config.FlannelAnnotationPrefix+"/"+flannelNodeAnnotationKeyPublicIP]
	if !ok {
		return fmt.Errorf("node %s missing annotation for Flannel public ip", node.Name)
	}
	if _, _, err := cnet.ParseCIDROrIP(publicIP); err != nil {
		return fmt.Errorf("node %s got wrong Flannel public ip '%s'", node.Name, publicIP)
	}

	type flannelVtepMac struct {
		VtepMAC string
	}
	var fvm flannelVtepMac
	err = json.Unmarshal([]byte(backendData), &fvm)
	if err != nil {
		return fmt.Errorf("node %s got wrong Flannel backend data %s", node.Name, backendData)
	}

	vtepMac := fvm.VtepMAC
	log.Infof("node %s has vxlan setup from Flannel (vtepMac: '%s', vtepIP: '%s').", node.Name, vtepMac, vtepIP.String())

	// Allocate Calico IPAM blocks for node.
	claimed, failed, err := m.calicoClient.IPAM().ClaimAffinity(m.ctx, *cidr, node.Name)
	if err != nil {
		log.WithError(err).Errorf("Failed to claim IPAM blocks for node %s, claimed %d, failed %d", node.Name, len(claimed), len(failed))
		return err
	}
	log.Infof("%d IPAM blocks claimed for node %s.", len(claimed), node.Name)

	// Update Calico node with Flannel vtep IP/Mac/publicIP.
	err = setupCalicoNodeVxlan(m.ctx, m.calicoClient, node.Name, *vtepIP, vtepMac, publicIP)
	if err != nil {
		return err
	}

	log.Infof("Setting up Calico IPAM for node %s completed successfully.", node.Name)
	return nil
}

// MigrateNodes setup Calico IPAM for array of nodes.
func (m ipamMigrator) MigrateNodes(nodes []*v1.Node) error {
	log.Infof("Start IPAM migration process for %d nodes.", len(nodes))
	for i, node := range nodes {
		log.Infof("Start setting up Calico IPAM for node %s[index %d].", node.Name, i)
		err := m.SetupCalicoIPAMForNode(node)
		if err != nil {
			return err
		}
	}
	log.Infof("%d nodes completed IPAM migration process.", len(nodes))

	return nil
}

// setupCalicoNodeVxlan assigns specified IP/Mac address as vtep IP/Mac address for Calico node.
func setupCalicoNodeVxlan(ctx context.Context, c client.Interface, nodeName string, vtepIP cnet.IP, mac, publicIP string) error {
	log.Infof("Updating Calico Node %s with vtep IP %s, Mac %s.", nodeName, vtepIP.String(), mac)

	// Assign vtep IP.
	// Check current status of vtep IP. It could be assigned already if migration controller restarts.
	assign := true
	attr, _, err := c.IPAM().GetAssignmentAttributes(ctx, vtepIP)
	if err == nil {
		if attr[ipam.AttributeType] == ipam.AttributeTypeVXLAN && attr[ipam.AttributeNode] == nodeName {
			// The tunnel address is still valid, do nothing.
			log.Infof("Calico Node %s vtep IP been assigned already.", nodeName)
			assign = false
		} else {
			// The tunnel address has been allocated to something else, return error.
			return fmt.Errorf("vtep IP %s has been occupied", vtepIP.String())
		}
	} else if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok {
		// The tunnel address is not assigned, assign it.
		log.WithField("vtepIP", vtepIP.String()).Info("assign a new vtep IP")
	} else {
		// Failed to get assignment attributes, datastore connection issues possible.
		log.WithError(err).Errorf("Failed to get assignment attributes for vtep IP '%s'", vtepIP.String())
		return fmt.Errorf("Failed to get vtep IP %s attribute", vtepIP.String())
	}

	if assign {
		// Build attributes and handle for this allocation.
		attrs := map[string]string{ipam.AttributeNode: nodeName}
		attrs[ipam.AttributeType] = ipam.AttributeTypeVXLAN
		handle := fmt.Sprintf("vxlan-tunnel-addr-%s", nodeName)

		err := c.IPAM().AssignIP(ctx, ipam.AssignIPArgs{
			IP:       vtepIP,
			Hostname: nodeName,
			HandleID: &handle,
			Attrs:    attrs,
		})
		if err != nil {
			return fmt.Errorf("Failed to assign vtep IP %s", vtepIP.String())
		}
		log.Infof("Calico Node %s vtep IP assigned.", nodeName)
	}

	// Update Calico node with vtep IP/Mac/PublicIP
	node, err := c.Nodes().Get(ctx, nodeName, options.GetOptions{})
	if err != nil {
		return err
	}

	// If node has correct vxlan setup, do nothing.
	if node.Spec.IPv4VXLANTunnelAddr == vtepIP.String() && node.Spec.VXLANTunnelMACAddr == mac &&
		(node.Spec.BGP != nil && node.Spec.BGP.IPv4Address == publicIP) {
		return nil
	}

	log.Infof("Calico Node current value: %+v.", node)

	node.Spec.BGP = &libapi.NodeBGPSpec{}
	// Set public ip with subnet /32.
	// The subnet part is required to pass Felix validation.
	node.Spec.BGP.IPv4Address = fmt.Sprintf("%s/32", publicIP)
	node.Spec.IPv4VXLANTunnelAddr = vtepIP.String()
	node.Spec.VXLANTunnelMACAddr = mac
	_, err = c.Nodes().Update(ctx, node, options.SetOptions{})
	if err != nil {
		return err
	}

	log.Infof("Calico Node %s vtep IP/Mac/PublicIP updated.", nodeName)
	return nil
}

// createIPPool creates an IP pool using the specified CIDR.
// If migrating from Flannel,
// - create or validate existing ippool.
// If migrating from Canal, default ippool would have vxlan disabled.
// - if vxlan is disabled, delete default ippool and create new one.
// - if vxlan is enabled, validate existing ippool.
func createDefaultVxlanIPPool(ctx context.Context, client client.Interface, cidr *cnet.IPNet, blockSize int, isNATOutgoingEnabled, checkVxlan bool) error {
	pool := &api.IPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name: defaultIpv4PoolName,
		},
		Spec: api.IPPoolSpec{
			CIDR:        cidr.String(),
			BlockSize:   blockSize,
			NATOutgoing: isNATOutgoingEnabled,
			IPIPMode:    api.IPIPModeNever,
			VXLANMode:   api.VXLANModeAlways,
		},
	}

	log.Infof("Ensure default IPv4 pool (cidr %s, blockSize %d, nat %t, vxlanMode %s).", cidr.String(), blockSize, isNATOutgoingEnabled, api.VXLANModeAlways)

	var defaultPool *api.IPPool
	var err error
	createPool := true
	if !checkVxlan {
		// Canal will always create a default ippool with vxlan disabled.
		defaultPool, err = client.IPPools().Get(ctx, defaultIpv4PoolName, options.GetOptions{})
		if err == nil {
			if defaultPool.Spec.VXLANMode != api.VXLANModeAlways {
				// ippool is created by Canal. Delete it
				_, err := client.IPPools().Delete(ctx, defaultIpv4PoolName, options.DeleteOptions{})
				if err != nil {
					log.WithError(err).Errorf("Failed to delete existing default IPv4 IP pool")
					return err
				}
			} else {
				// We have a default pool and vxlan mode is enabled.
				createPool = false
			}
		} else {
			if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok {
				log.WithError(err).Errorf("Failed to get default IPv4 pool for Canal")
				return err
			}
			log.WithError(err).Warnf("Default IPv4 pool for Canal not exists")
		}
	}

	if createPool {
		// Create the pool.
		// Validate if pool already exists.
		_, err = client.IPPools().Create(ctx, pool, options.SetOptions{})
		if err == nil {
			log.Info("Created default IPv4 pool.")
			return nil
		}

		if _, ok := err.(cerrors.ErrorResourceAlreadyExists); !ok {
			log.WithError(err).Errorf("Failed to create default IPv4 pool (%s)", cidr.String())
			return err
		}

		// Default pool exists.
		defaultPool, err = client.IPPools().Get(ctx, defaultIpv4PoolName, options.GetOptions{})
		if err != nil {
			log.WithError(err).Errorf("Failed to get existing default IPv4 IP pool")
			return err
		}
	}

	// Check CIDR/blockSize/NATOutgoing for existing pool.
	if defaultPool.Spec.CIDR != cidr.String() ||
		defaultPool.Spec.BlockSize != blockSize ||
		defaultPool.Spec.NATOutgoing != isNATOutgoingEnabled ||
		defaultPool.Spec.VXLANMode != api.VXLANModeAlways {
		msg := fmt.Sprintf("current [cidr:%s, blocksize:%d, nat:%t, vxlanMode %s], expected [cidr:%s, blocksize:%d, nat:%t, vxlanMode %s]",
			defaultPool.Spec.CIDR, defaultPool.Spec.BlockSize, defaultPool.Spec.NATOutgoing, defaultPool.Spec.VXLANMode,
			cidr.String(), blockSize, isNATOutgoingEnabled, api.VXLANModeAlways)
		log.Errorf("Failed to validate existing default IPv4 IP pool (cidr/blocksize/nat/vxlanMode) %+v", defaultPool.Spec)
		return cerrors.ErrorValidation{
			ErroredFields: []cerrors.ErroredField{{
				Name:   "pool.Spec",
				Reason: msg,
			}},
		}
	}

	log.Info("Use current default IPv4 pool.")
	return nil
}

// Update default FelixConfiguration with specified VNI, port and MTU.
// If migrating from Flannel, return error if vxlan is not enabled.
// If migrating from Canal, set vxlan enabled.
// Do nothing if correct values already been set.
func updateOrCreateDefaultFelixConfiguration(ctx context.Context, client client.Interface, vni, port, mtu int, checkVxlan bool) error {
	// Get default Felix configuration. Return error if not exists.
	defaultConfig, err := client.FelixConfigurations().Get(ctx, defaultFelixConfigurationName, options.GetOptions{})
	if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok {
		// Create the default config if it doesn't already exist.
		defaultConfig = api.NewFelixConfiguration()
		defaultConfig.Name = defaultFelixConfigurationName
		t := true
		defaultConfig.Spec.VXLANEnabled = &t
		defaultConfig, err = client.FelixConfigurations().Create(ctx, defaultConfig, options.SetOptions{})
	}
	if err != nil {
		log.WithError(err).Errorf("Error creating default FelixConfiguration resource")
		return err
	}

	if checkVxlan {
		// Check if vxlan is enabled. Return error if not.
		vxlanEnabled := false
		if defaultConfig.Spec.VXLANEnabled != nil {
			vxlanEnabled = *defaultConfig.Spec.VXLANEnabled
		}
		if !vxlanEnabled {
			log.WithError(err).Errorf("vxlan is not enabled by default Felix configration")
			return err
		}
	}

	// Get current value for vxlanEnabled, VNI , Port and MTU.
	currentVxlanEnabled := false
	if defaultConfig.Spec.VXLANEnabled != nil {
		currentVxlanEnabled = *defaultConfig.Spec.VXLANEnabled
	}
	currentVNI := 0
	if defaultConfig.Spec.VXLANVNI != nil {
		currentVNI = *defaultConfig.Spec.VXLANVNI
	}
	currentPort := 0
	if defaultConfig.Spec.VXLANPort != nil {
		currentPort = *defaultConfig.Spec.VXLANPort
	}
	currentMTU := 0
	if defaultConfig.Spec.VXLANMTU != nil {
		currentMTU = *defaultConfig.Spec.VXLANMTU
	}

	// Do nothing if the correct value has been set.
	if currentVNI == vni && currentPort == port && currentMTU == mtu && currentVxlanEnabled {
		log.Infof("Default Felix configration got correct vxlanEnabled, VNI(%d), port(%d), mtu(%d).", currentVNI, currentPort, currentMTU)
		return nil
	}

	vxlanEnabled := true
	defaultConfig.Spec.VXLANEnabled = &vxlanEnabled
	defaultConfig.Spec.VXLANVNI = &vni
	defaultConfig.Spec.VXLANPort = &port
	defaultConfig.Spec.VXLANMTU = &mtu
	_, err = client.FelixConfigurations().Update(ctx, defaultConfig, options.SetOptions{})
	if err != nil {
		log.WithError(err).Errorf("Failed to update default FelixConfiguration.")
		return err
	}

	log.Info("default FelixConfiguration updated successfully")
	return nil
}
