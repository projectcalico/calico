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

package mocknetlink

import (
	"sort"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/netlinkshim"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

/*
var WireguardFailureScenarios = []FailFlags{
	FailNone,
	FailNextLinkAdd,
	FailNextLinkAddNotSupported,
	FailNextLinkDel,
	FailNextLinkSetMTU,
	FailNextLinkSetUp,
	FailNextLinkByName,
	FailNextLinkByNameNotFound,
	FailNextRouteList,
	FailNextRouteAdd,
	FailNextRouteDel,
	FailNextAddARP,
	FailNextNewNetlink,
	FailNextSetSocketTimeout,
	FailNextRuleAdd,
	FailNextRuleDel,
	FailNextNewWireguard,
	FailNextNewWireguardNotSupported,
	FailNextWireguardClose,
	FailNextWireguardDeviceByName,
	FailNextWireguardConfigureDevice,
}
*/

// ----- Mock dataplane management functions for test code -----

func (d *MockNetlinkDataplane) NewMockWireguard() (netlinkshim.Wireguard, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer GinkgoRecover()

	d.NumNewWireguardCalls++
	if d.PersistentlyFailToConnect || d.shouldFail(FailNextNewWireguard) {
		return nil, SimulatedError
	}
	if d.shouldFail(FailNextNewWireguardNotSupported) {
		return nil, NotSupportedError
	}
	Expect(d.WireguardOpen).To(BeFalse())
	d.WireguardOpen = true
	return d, nil
}

// ----- Wireguard API -----

func (d *MockNetlinkDataplane) Close() error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer GinkgoRecover()

	Expect(d.WireguardOpen).To(BeTrue())
	d.WireguardOpen = false
	if d.shouldFail(FailNextWireguardClose) {
		return SimulatedError
	}

	return nil
}

func (d *MockNetlinkDataplane) DeviceByName(name string) (*wgtypes.Device, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer GinkgoRecover()

	Expect(d.WireguardOpen).To(BeTrue())
	if d.shouldFail(FailNextWireguardDeviceByName) {
		return nil, SimulatedError
	}
	link, ok := d.NameToLink[name]
	if !ok {
		return nil, NotFoundError
	}
	if link.Type() != "wireguard" {
		return nil, FileDoesNotExistError
	}

	device := &wgtypes.Device{
		Name:         name,
		Type:         wgtypes.LinuxKernel,
		PrivateKey:   link.WireguardPrivateKey,
		PublicKey:    link.WireguardPublicKey,
		ListenPort:   link.WireguardListenPort,
		FirewallMark: link.WireguardFirewallMark,
	}
	for _, peer := range link.WireguardPeers {
		device.Peers = append(device.Peers, peer)
	}

	return device, nil
}

func (d *MockNetlinkDataplane) Devices() ([]*wgtypes.Device, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer GinkgoRecover()

	Expect(d.WireguardOpen).To(BeTrue())
	if d.shouldFail(FailNextWireguardDeviceByName) {
		return nil, SimulatedError
	}

	links := []*wgtypes.Device{}

	for name, link := range d.NameToLink {
		device := &wgtypes.Device{
			Name:         name,
			Type:         wgtypes.LinuxKernel,
			PrivateKey:   link.WireguardPrivateKey,
			PublicKey:    link.WireguardPublicKey,
			ListenPort:   link.WireguardListenPort,
			FirewallMark: link.WireguardFirewallMark,
		}
		links = append(links, device)
	}

	return links, nil
}

func (d *MockNetlinkDataplane) ConfigureDevice(name string, cfg wgtypes.Config) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer GinkgoRecover()

	// Track the last set of wireguard device updates. Note that we should only get each peer appearing at most once in
	// the update.
	d.LastWireguardUpdates = make(map[wgtypes.Key]wgtypes.PeerConfig)
	for _, p := range cfg.Peers {
		d.LastWireguardUpdates[p.PublicKey] = p
	}
	Expect(cfg.Peers).To(HaveLen(len(d.LastWireguardUpdates)))

	Expect(d.WireguardOpen).To(BeTrue())
	if d.shouldFail(FailNextWireguardConfigureDevice) {
		return SimulatedError
	}
	link, ok := d.NameToLink[name]
	if !ok {
		return NotFoundError
	}

	if cfg.FirewallMark != nil {
		link.WireguardFirewallMark = *cfg.FirewallMark
		d.WireguardConfigUpdated = true
	}
	if cfg.ListenPort != nil {
		link.WireguardListenPort = *cfg.ListenPort
		d.WireguardConfigUpdated = true
	}
	if cfg.PrivateKey != nil {
		link.WireguardPrivateKey = *cfg.PrivateKey
		link.WireguardPublicKey = link.WireguardPrivateKey.PublicKey()
		d.WireguardConfigUpdated = true
	}
	if cfg.ReplacePeers || len(cfg.Peers) > 0 {
		logrus.Debug("Update peers for wireguard link")
		existing := link.WireguardPeers
		if cfg.ReplacePeers || link.WireguardPeers == nil {
			logrus.Debug("Reset internal peers map")
			link.WireguardPeers = map[wgtypes.Key]wgtypes.Peer{}
		}
		for _, peerCfg := range cfg.Peers {
			d.WireguardConfigUpdated = true
			Expect(peerCfg.PublicKey).NotTo(Equal(wgtypes.Key{}))
			if peerCfg.UpdateOnly {
				_, ok := existing[peerCfg.PublicKey]
				Expect(ok).To(BeTrue())
			}
			if peerCfg.Remove {
				_, ok := existing[peerCfg.PublicKey]
				Expect(ok).To(BeTrue())
				delete(existing, peerCfg.PublicKey)
				continue
			}

			// Get the current peer settings so we can apply the deltas.
			peer := link.WireguardPeers[peerCfg.PublicKey]

			// Store the public key (this may be zero if the peer ff not exist).
			peer.PublicKey = peerCfg.PublicKey

			// Apply updates.
			if peerCfg.Endpoint != nil {
				peer.Endpoint = peerCfg.Endpoint
			}
			if peerCfg.PersistentKeepaliveInterval != nil {
				peer.PersistentKeepaliveInterval = *peerCfg.PersistentKeepaliveInterval
			}

			// Construct the set of allowed IPs and then transfer to the slice for storage. We sort these so our tests
			// can be deterministic.
			allowedIPs := set.New[string]()
			if !peerCfg.ReplaceAllowedIPs {
				for _, ipnet := range peer.AllowedIPs {
					allowedIPs.Add(ipnet.String())
				}
			}
			if len(peerCfg.AllowedIPs) > 0 {
				for _, ipnet := range peerCfg.AllowedIPs {
					allowedIPs.Add(ipnet.String())
				}
			}

			var allowedIPStr []string
			allowedIPs.Iter(func(allowedIP string) error {
				allowedIPStr = append(allowedIPStr, allowedIP)
				return nil
			})
			sort.Strings(allowedIPStr)

			peer.AllowedIPs = nil
			for _, ipstr := range allowedIPStr {
				peer.AllowedIPs = append(peer.AllowedIPs, ip.MustParseCIDROrIP(ipstr).ToIPNet())
			}

			// Store the peer.
			link.WireguardPeers[peerCfg.PublicKey] = peer
		}
	}

	return nil
}
