// Copyright (c) 2019-2021 Tigera, Inc. All rights reserved.

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

package updateprocessors

import (
	"errors"
	"fmt"

	log "github.com/sirupsen/logrus"

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/watchersyncer"
	cresources "github.com/projectcalico/calico/libcalico-go/lib/resources"

	wg "golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// Create a new SyncerUpdateProcessor to sync Node data in v1 format for
// consumption by Felix.
func NewFelixNodeUpdateProcessor(usePodCIDR bool) watchersyncer.SyncerUpdateProcessor {
	return &FelixNodeUpdateProcessor{
		usePodCIDR:      usePodCIDR,
		nodeCIDRTracker: newNodeCIDRTracker(),
	}
}

// FelixNodeUpdateProcessor implements the SyncerUpdateProcessor interface.
// This converts the v3 node configuration into the v1 data types consumed by confd.
type FelixNodeUpdateProcessor struct {
	usePodCIDR      bool
	nodeCIDRTracker nodeCIDRTracker
}

func (c *FelixNodeUpdateProcessor) Process(kvp *model.KVPair) ([]*model.KVPair, error) {
	// Extract the name.
	name, err := c.extractName(kvp.Key)
	if err != nil {
		return nil, err
	}

	// Extract the separate bits of BGP config - these are stored as separate keys in the
	// v1 model.  For a delete these will all be nil.  If we fail to convert any value then
	// just treat that as a delete on the underlying key and return the error alongside
	// the updates.
	var ipv4, ipv4Tunl, vxlanTunlIp, vxlanTunlMac, vxlanV6TunlIp, vxlanV6TunlMac, wgConfig interface{}
	var node *libapiv3.Node
	var ok bool
	if kvp.Value != nil {
		node, ok = kvp.Value.(*libapiv3.Node)
		if !ok {
			return nil, errors.New("Incorrect value type - expecting resource of kind Node")
		}

		if bgp := node.Spec.BGP; bgp != nil {
			var ip *cnet.IP
			var cidr *cnet.IPNet

			// Parse the IPv4 address, Felix expects this as a HostIPKey.  If we fail to parse then
			// treat as a delete (i.e. leave ipv4 as nil).
			if len(bgp.IPv4Address) != 0 {
				ip, cidr, err = cnet.ParseCIDROrIP(bgp.IPv4Address)
				if err == nil {
					log.WithFields(log.Fields{"ip": ip, "cidr": cidr}).Debug("Parsed IPv4 address")
					ipv4 = ip
				} else {
					log.WithError(err).WithField("IPv4Address", bgp.IPv4Address).Warn("Failed to parse IPv4Address")
				}
			}

			// Parse the IPv4 IPIP tunnel address, Felix expects this as a HostConfigKey.  If we fail to parse then
			// treat as a delete (i.e. leave ipv4Tunl as nil).
			if len(bgp.IPv4IPIPTunnelAddr) != 0 {
				ip := cnet.ParseIP(bgp.IPv4IPIPTunnelAddr)
				if ip != nil {
					log.WithField("ip", ip).Debug("Parsed IPIP tunnel address")
					ipv4Tunl = ip.String()
				} else {
					log.WithField("IPv4IPIPTunnelAddr", bgp.IPv4IPIPTunnelAddr).Warn("Failed to parse IPv4IPIPTunnelAddr")
					err = fmt.Errorf("failed to parsed IPv4IPIPTunnelAddr as an IP address")
				}
			}
		}
		// Look for internal node address, if BGP is not running
		if ipv4 == nil {
			ip, _ := cresources.FindNodeAddress(node, libapiv3.InternalIP, 4)
			if ip != nil {
				ipv4 = ip
			}
		}
		if ipv4 == nil {
			ip, _ := cresources.FindNodeAddress(node, libapiv3.ExternalIP, 4)
			if ip != nil {
				ipv4 = ip
			}
		}

		// Parse the IPv4 VXLAN tunnel address, Felix expects this as a HostConfigKey.  If we fail to parse then
		// treat as a delete (i.e. leave vxlanTunlIp as nil).
		if len(node.Spec.IPv4VXLANTunnelAddr) != 0 {
			ip := cnet.ParseIP(node.Spec.IPv4VXLANTunnelAddr)
			if ip != nil {
				log.WithField("ip", ip).Debug("Parsed IPv4 VXLAN tunnel address")
				vxlanTunlIp = ip.String()
			} else {
				log.WithField("IPv4VXLANTunnelAddr", node.Spec.IPv4VXLANTunnelAddr).Warn("Failed to parse IPv4VXLANTunnelAddr")
				err = fmt.Errorf("failed to parse IPv4VXLANTunnelAddr as an IP address")
			}
		}

		// Parse the VXLAN tunnel MAC address, Felix expects this as a HostConfigKey.  If we fail to parse then
		// treat as a delete (i.e. leave vxlanTunlMac as nil).
		if len(node.Spec.VXLANTunnelMACAddr) != 0 {
			mac := node.Spec.VXLANTunnelMACAddr
			if mac != "" {
				log.WithField("mac addr", mac).Debug("Parsed IPv4 VXLAN tunnel MAC address")
				vxlanTunlMac = mac
			} else {
				log.WithField("VXLANTunnelMACAddr", node.Spec.VXLANTunnelMACAddr).Warn("VXLANTunnelMACAddr not populated")
				err = fmt.Errorf("failed to update VXLANTunnelMACAddr")
			}
		}

		// Parse the IPv6 VXLAN tunnel address, Felix expects this as a HostConfigKey.  If we fail to parse then
		// treat as a delete (i.e. leave vxlanV6TunlIp as nil).
		if len(node.Spec.IPv6VXLANTunnelAddr) != 0 {
			ip := cnet.ParseIP(node.Spec.IPv6VXLANTunnelAddr)
			if ip != nil {
				log.WithField("ip", ip).Debug("Parsed IPv6 VXLAN tunnel address")
				vxlanV6TunlIp = ip.String()
			} else {
				log.WithField("IPv6VXLANTunnelAddr", node.Spec.IPv6VXLANTunnelAddr).Warn("Failed to parse IPv6VXLANTunnelAddr")
				err = fmt.Errorf("failed to parse IPv6VXLANTunnelAddr as an IP address")
			}
		}

		// Parse the IPv6 VXLAN tunnel MAC address, Felix expects this as a HostConfigKey.  If we fail to parse then
		// treat as a delete (i.e. leave vxlanV6TunlMac as nil).
		if len(node.Spec.VXLANTunnelMACAddrV6) != 0 {
			mac := node.Spec.VXLANTunnelMACAddrV6
			if mac != "" {
				log.WithField("mac addr", mac).Debug("Parsed IPv6 VXLAN tunnel MAC address")
				vxlanV6TunlMac = mac
			} else {
				log.WithField("VXLANTunnelMACAddrV6", node.Spec.VXLANTunnelMACAddrV6).Warn("VXLANTunnelMACAddrV6 not populated")
				err = fmt.Errorf("failed to update VXLANTunnelMACAddrV6")
			}
		}

		var wgIfaceIpv4Addr *cnet.IP
		var wgPubKey string
		if wgSpec := node.Spec.Wireguard; wgSpec != nil {
			if len(wgSpec.InterfaceIPv4Address) != 0 {
				wgIfaceIpv4Addr = cnet.ParseIP(wgSpec.InterfaceIPv4Address)
				if wgIfaceIpv4Addr != nil {
					log.WithField("InterfaceIPv4Addr", wgIfaceIpv4Addr).Debug("Parsed IPv4 Wireguard interface address")
				} else {
					log.WithField("InterfaceIPv4Addr", wgSpec.InterfaceIPv4Address).Warn("Failed to parse InterfaceIPv4Address")
					err = fmt.Errorf("failed to parse InterfaceIPv4Address as an IP address")
				}
			}
		}
		if wgPubKey = node.Status.WireguardPublicKey; wgPubKey != "" {
			_, err := wg.ParseKey(wgPubKey)
			if err == nil {
				log.WithField("public-key", wgPubKey).Debug("Parsed IPv4 Wireguard public-key")
			} else {
				log.WithField("WireguardPublicKey", wgPubKey).Warn("Failed to parse IPv4 Wireguard public-key")
				err = fmt.Errorf("failed to parse PublicKey as IPv4 Wireguard public-key")
			}
		}

		var wgIfaceIpv6Addr *cnet.IP
		var wgPubKeyV6 string
		if wgSpec := node.Spec.Wireguard; wgSpec != nil {
			if len(wgSpec.InterfaceIPv6Address) != 0 {
				wgIfaceIpv6Addr = cnet.ParseIP(wgSpec.InterfaceIPv6Address)
				if wgIfaceIpv6Addr != nil {
					log.WithField("InterfaceIPv6Addr", wgIfaceIpv6Addr).Debug("Parsed IPv6 Wireguard interface address")
				} else {
					log.WithField("InterfaceIPv6Addr", wgSpec.InterfaceIPv6Address).Warn("Failed to parse InterfaceIPv6Address")
					err = fmt.Errorf("failed to parse InterfaceIPv6Address as an IP address")
				}
			}
		}
		if wgPubKeyV6 = node.Status.WireguardPublicKeyV6; wgPubKeyV6 != "" {
			_, err := wg.ParseKey(wgPubKeyV6)
			if err == nil {
				log.WithField("public-key", wgPubKeyV6).Debug("Parsed IPv6 Wireguard public-key")
			} else {
				log.WithField("WireguardPublicKeyV6", wgPubKeyV6).Warn("Failed to parse IPv6 Wireguard public-key")
				err = fmt.Errorf("failed to parse PublicKeyV6 as IPv6 Wireguard public-key")
			}
		}

		// If either of interface address or public-key is set, set the WireguardKey value.
		// If we failed to parse both the values, leave the WireguardKey value empty.
		if wgIfaceIpv4Addr != nil || wgPubKey != "" || wgIfaceIpv6Addr != nil || wgPubKeyV6 != "" {
			wgConfig = &model.Wireguard{
				InterfaceIPv4Addr: wgIfaceIpv4Addr,
				PublicKey:         wgPubKey,
				InterfaceIPv6Addr: wgIfaceIpv6Addr,
				PublicKeyV6:       wgPubKeyV6,
			}
		}
	}

	kvps := []*model.KVPair{
		{
			Key: model.HostIPKey{
				Hostname: name,
			},
			Value:    ipv4,
			Revision: kvp.Revision,
		},
		{
			Key: model.HostConfigKey{
				Hostname: name,
				Name:     "IpInIpTunnelAddr",
			},
			Value:    ipv4Tunl,
			Revision: kvp.Revision,
		},
		{
			Key: model.HostConfigKey{
				Hostname: name,
				Name:     "IPv4VXLANTunnelAddr",
			},
			Value:    vxlanTunlIp,
			Revision: kvp.Revision,
		},
		{
			Key: model.HostConfigKey{
				Hostname: name,
				Name:     "VXLANTunnelMACAddr",
			},
			Value:    vxlanTunlMac,
			Revision: kvp.Revision,
		},
		{
			Key: model.HostConfigKey{
				Hostname: name,
				Name:     "IPv6VXLANTunnelAddr",
			},
			Value:    vxlanV6TunlIp,
			Revision: kvp.Revision,
		},
		{
			Key: model.HostConfigKey{
				Hostname: name,
				Name:     "VXLANTunnelMACAddrV6",
			},
			Value:    vxlanV6TunlMac,
			Revision: kvp.Revision,
		},
		{
			// Include the original node KVP info as a separate update. Note we do not use the node value here because
			// a nil interface is different to a nil pointer. Felix and other code assumes a nil Value is a delete, so
			// preserve that relationship here.
			Key: model.ResourceKey{
				Name: name,
				Kind: libapiv3.KindNode,
			},
			Value:    kvp.Value,
			Revision: kvp.Revision,
		},
		{
			Key: model.WireguardKey{
				NodeName: name,
			},
			Value:    wgConfig,
			Revision: kvp.Revision,
		},
	}

	if c.usePodCIDR {
		// If we're using host-local IPAM based off the Kubernetes node PodCIDR, then
		// we need to send Blocks based on the CIDRs to felix.
		log.Debug("Using pod cidr")
		var currentPodCIDRs []string
		if node != nil {
			currentPodCIDRs = node.Status.PodCIDRs
		}
		toRemove := c.nodeCIDRTracker.SetNodeCIDRs(name, currentPodCIDRs)
		log.Debugf("Current CIDRS: %s", currentPodCIDRs)
		log.Debugf("Old CIDRS: %s", toRemove)

		// Send deletes for any CIDRs which are no longer present.
		for _, c := range toRemove {
			_, cidr, err := cnet.ParseCIDR(c)
			if err != nil {
				log.WithError(err).WithField("CIDR", c).Warn("Failed to parse Node PodCIDR")
				continue
			}
			kvps = append(kvps, &model.KVPair{
				Key:      model.BlockKey{CIDR: *cidr},
				Value:    nil,
				Revision: kvp.Revision,
			})
		}

		// Send updates for any CIDRs which are still present.
		for _, c := range currentPodCIDRs {
			_, cidr, err := cnet.ParseCIDR(c)
			if err != nil {
				log.WithError(err).WithField("CIDR", c).Warn("Failed to parse Node PodCIDR")
				continue
			}

			aff := fmt.Sprintf("host:%s", name)
			kvps = append(kvps, &model.KVPair{
				Key:      model.BlockKey{CIDR: *cidr},
				Value:    &model.AllocationBlock{CIDR: *cidr, Affinity: &aff},
				Revision: kvp.Revision,
			})
		}
	}

	return kvps, err
}

// Sync is restarting - nothing to do for this processor.
func (c *FelixNodeUpdateProcessor) OnSyncerStarting() {
	log.Debug("Sync starting called on Felix node update processor")
}

func (c *FelixNodeUpdateProcessor) extractName(k model.Key) (string, error) {
	rk, ok := k.(model.ResourceKey)
	if !ok || rk.Kind != libapiv3.KindNode {
		return "", errors.New("Incorrect key type - expecting resource of kind Node")
	}
	return rk.Name, nil
}
