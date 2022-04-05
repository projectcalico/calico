// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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

package wireguard_test

import (
	"bytes"
	"net"
	"text/template"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/netlinkshim"
	"github.com/projectcalico/calico/felix/wireguard"
)

var _ netlinkshim.Wireguard = (*wireguardDevicesOnly)(nil)

type wireguardDevicesOnly struct {
	name               string
	listenPort, fwMark int
	privateKey         wgtypes.Key
	peers              []*wgtypes.Peer
}

func newMockPeeredWireguardDevice(privateKey wgtypes.Key, peers []*wgtypes.Peer) *wireguardDevicesOnly {
	return &wireguardDevicesOnly{
		name:       "wireguard.cali",
		listenPort: 51820,
		fwMark:     0x1000000001,
		privateKey: privateKey,
		peers:      peers,
	}
}

type mockPeerInfo struct {
	privKey wgtypes.Key
	peer    *wgtypes.Peer
}

func mustPrivateKey() wgtypes.Key {
	pk, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		panic(err)
	}
	return pk
}

func mustNewMockPeer(ipAddr string, port int) *mockPeerInfo {
	privKey := mustPrivateKey()
	peer := &wgtypes.Peer{
		PublicKey:       privKey.PublicKey(),
		Endpoint:        &net.UDPAddr{IP: ip.FromString(ipAddr).AsNetIP(), Port: port},
		ProtocolVersion: 4,
	}

	return &mockPeerInfo{privKey, peer}
}

func (w *wireguardDevicesOnly) Close() error {
	return nil
}

func (w *wireguardDevicesOnly) DeviceByName(name string) (*wgtypes.Device, error) {
	dev := &wgtypes.Device{
		Name:         name,
		Type:         wgtypes.LinuxKernel,
		PrivateKey:   w.privateKey,
		PublicKey:    w.privateKey.PublicKey(),
		ListenPort:   w.listenPort,
		FirewallMark: w.fwMark,
	}

	for _, peer := range w.peers {
		dev.Peers = append(dev.Peers, *peer)
	}

	return dev, nil
}

func (w *wireguardDevicesOnly) Devices() ([]*wgtypes.Device, error) {
	dev, _ := w.DeviceByName(w.name)
	return []*wgtypes.Device{dev}, nil
}

func (w *wireguardDevicesOnly) ConfigureDevice(_ string, _ wgtypes.Config) error {
	return nil
}

func (w *wireguardDevicesOnly) generatePeerTraffic(rx, tx int64) time.Time {
	ts := time.Now()
	for _, peer := range w.peers {
		peer.ReceiveBytes += rx
		peer.TransmitBytes += tx
		peer.LastHandshakeTime = time.Now()
	}
	return ts
}

var _ = Describe("wireguard metrics", func() {
	var wgStats *wireguard.Metrics
	var wgClient *wireguardDevicesOnly
	var mockPeers []*mockPeerInfo
	const (
		hostname                 = "l0c4lh057"
		defaultRateLimitInterval = time.Second * 5
	)

	newWireguardDevicesOnly := func() (netlinkshim.Wireguard, error) {
		return wgClient, nil
	}

	BeforeEach(func() {
		mockPeers = []*mockPeerInfo{
			mustNewMockPeer("10.0.0.1", 1001),
			mustNewMockPeer("10.0.0.2", 1002),
		}
		wgClient = newMockPeeredWireguardDevice(mockPeers[0].privKey, []*wgtypes.Peer{
			mockPeers[1].peer,
		})
		wgStats = wireguard.NewWireguardMetricsWithShims(
			hostname,
			newWireguardDevicesOnly,
			defaultRateLimitInterval,
		)
	})

	It("should yield metrics", func() {
		By("checking if it's constructable")
		Expect(wgStats).ToNot(BeNil())

		By("registering it in a prometheus.Registry")
		registry := prometheus.NewRegistry()
		registry.MustRegister(wgStats)

		By("producing metrics")
		wgClient.generatePeerTraffic(512, 512)
		mfs, err := registry.Gather()
		Expect(err).ToNot(HaveOccurred())
		Expect(mfs).To(HaveLen(4))

		By("checking if rate-limiting works")
		mfs2, err := registry.Gather()
		Expect(err).ToNot(HaveOccurred())
		Expect(mfs2).To(BeEmpty())

		<-time.After(5 * time.Second)
		ts := wgClient.generatePeerTraffic(1024, 1024)
		mfs, err = registry.Gather()
		Expect(err).ToNot(HaveOccurred())
		Expect(mfs).To(HaveLen(4))

		By("comparing text output")
		buf := &bytes.Buffer{}
		for _, mf := range mfs {
			_, err := expfmt.MetricFamilyToText(buf, mf)
			Expect(err).ToNot(HaveOccurred())
		}

		data := map[string]interface{}{
			"pubkey":     mockPeers[0].peer.PublicKey.String(),
			"peerkey":    mockPeers[1].peer.PublicKey.String(),
			"endpoint":   mockPeers[1].peer.Endpoint.String(),
			"hostname":   hostname,
			"iface":      wgClient.name,
			"listenport": wgClient.listenPort,
			"ts":         float64(ts.Unix()),
		}

		tmpl := template.Must(
			template.New("").Parse(`# HELP wireguard_bytes_rcvd wireguard interface incoming bytes count from peer
# TYPE wireguard_bytes_rcvd counter
wireguard_bytes_rcvd{hostname="{{.hostname}}",peer_endpoint="{{.endpoint}}",peer_key="{{.peerkey}}",public_key="{{.pubkey}}"} 1536
# HELP wireguard_bytes_sent wireguard interface outgoing bytes count to peer
# TYPE wireguard_bytes_sent counter
wireguard_bytes_sent{hostname="{{.hostname}}",peer_endpoint="{{.endpoint}}",peer_key="{{.peerkey}}",public_key="{{.pubkey}}"} 1536
# HELP wireguard_latest_handshake_seconds wireguard interface latest handshake unix timestamp in seconds to a peer
# TYPE wireguard_latest_handshake_seconds gauge
wireguard_latest_handshake_seconds{hostname="{{.hostname}}",peer_endpoint="{{.endpoint}}",peer_key="{{.peerkey}}",public_key="{{.pubkey}}"} {{.ts}}
# HELP wireguard_meta wireguard interface and runtime metadata
# TYPE wireguard_meta gauge
wireguard_meta{hostname="{{.hostname}}",iface="{{.iface}}",listen_port="{{.listenport}}",public_key="{{.pubkey}}"} 1
`))
		buf2 := &bytes.Buffer{}
		err = tmpl.Execute(buf2, data)
		Expect(err).ToNot(HaveOccurred())

		Expect(buf.String()).To(Equal(buf2.String()))
	})

	It("should not yield metrics if unregistered", func() {
		By("checking if it's constructable")
		Expect(wgStats).ToNot(BeNil())

		By("registering it in a prometheus.Registry")
		registry := prometheus.NewRegistry()
		registry.MustRegister(wgStats)

		By("unregistering with no issue")
		ok := registry.Unregister(wgStats)
		Expect(ok).To(BeTrue())

		By("checking if gathering metrics will not error")
		wgClient.generatePeerTraffic(512, 512)
		mfs, err := registry.Gather()
		Expect(err).ToNot(HaveOccurred())

		By("checking if there are no metrics at all since it is unregistered")
		Expect(mfs).To(HaveLen(0))
	})

	AfterEach(func() {
		wgClient = nil
	})
})
