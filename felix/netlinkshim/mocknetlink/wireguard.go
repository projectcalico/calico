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

	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
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
	defer ginkgo.GinkgoRecover()

	d.NumNewWireguardCalls++
	if d.PersistentlyFailToConnect || d.shouldFail(FailNextNewWireguard) {
		return nil, ErrSimulated
	}
	if d.shouldFail(FailNextNewWireguardNotSupported) {
		return nil, ErrNotSupported
	}
	gomega.Expect(d.WireguardOpen).To(gomega.BeFalse())
	d.WireguardOpen = true

	return &MockWireguard{d}, nil
}

// ----- Wireguard API -----

type MockWireguard struct {
	*MockNetlinkDataplane
}

func (d *MockWireguard) Close() error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer ginkgo.GinkgoRecover()

	gomega.Expect(d.WireguardOpen).To(gomega.BeTrue())
	d.WireguardOpen = false
	if d.shouldFail(FailNextWireguardClose) {
		return ErrSimulated
	}

	return nil
}

func (d *MockWireguard) DeviceByName(name string) (*wgtypes.Device, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer ginkgo.GinkgoRecover()

	gomega.Expect(d.WireguardOpen).To(gomega.BeTrue())
	if d.shouldFail(FailNextWireguardDeviceByName) {
		return nil, ErrSimulated
	}
	link, ok := d.NameToLink[name]
	if !ok {
		return nil, ErrNotFound
	}
	if link.Type() != "wireguard" {
		return nil, ErrFileDoesNotExist
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

func (d *MockWireguard) Devices() ([]*wgtypes.Device, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer ginkgo.GinkgoRecover()

	gomega.Expect(d.WireguardOpen).To(gomega.BeTrue())
	if d.shouldFail(FailNextWireguardDeviceByName) {
		return nil, ErrSimulated
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

func (d *MockWireguard) ConfigureDevice(name string, cfg wgtypes.Config) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer ginkgo.GinkgoRecover()

	// Track the last set of wireguard device updates. Note that we should only get each peer appearing at most once in
	// the update.
	d.LastWireguardUpdates = make(map[wgtypes.Key]wgtypes.PeerConfig)
	for _, p := range cfg.Peers {
		d.LastWireguardUpdates[p.PublicKey] = p
	}
	gomega.Expect(cfg.Peers).To(gomega.HaveLen(len(d.LastWireguardUpdates)))

	gomega.Expect(d.WireguardOpen).To(gomega.BeTrue())
	if d.shouldFail(FailNextWireguardConfigureDevice) {
		return ErrSimulated
	}
	link, ok := d.NameToLink[name]
	if !ok {
		return ErrNotFound
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
			gomega.Expect(peerCfg.PublicKey).NotTo(gomega.Equal(wgtypes.Key{}))
			if peerCfg.UpdateOnly {
				_, ok := existing[peerCfg.PublicKey]
				gomega.Expect(ok).To(gomega.BeTrue())
			}
			if peerCfg.Remove {
				_, ok := existing[peerCfg.PublicKey]
				gomega.Expect(ok).To(gomega.BeTrue())
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
			for allowedIP := range allowedIPs.All() {
				allowedIPStr = append(allowedIPStr, allowedIP)
			}
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
