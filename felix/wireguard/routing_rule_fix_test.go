package wireguard_test

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"k8s.io/utils/ptr"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/logutils"
	mocknetlink "github.com/projectcalico/calico/felix/netlinkshim/mocknetlink"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/felix/timeshim/mocktime"
	. "github.com/projectcalico/calico/felix/wireguard"
)

var _ = Describe("Source-scoped routing rules fix (Issue #9751)", func() {
	var (
		wg            *Wireguard
		wgDataplane   *mocknetlink.MockDataplane
		rtDataplane   *mocknetlink.MockDataplane
		rrDataplane   *mocknetlink.MockDataplane
		t             *mocktime.MockTime
		config        *Config
		s             *mockStatus
		hostname      = "test-node"
		peer1         = "peer1"
		ipv4_local    = ip.FromString("10.0.0.1")
		ipv4_peer1    = ip.FromString("10.0.0.2")
		cidr_pool1    = ip.MustParseCIDROrIP("10.161.0.0/16")
		cidr_pool2    = ip.MustParseCIDROrIP("10.162.0.0/16")
		cidr_workload = ip.MustParseCIDROrIP("10.161.100.10/32")
		rulePriority  = 99
		tableIndex    = 1000
		firewallMark  = uint32(0xa)
	)

	BeforeEach(func() {
		wgDataplane = mocknetlink.New()
		rtDataplane = mocknetlink.New()
		rrDataplane = mocknetlink.New()
		s = &mockStatus{}
		t = mocktime.New()
		t.SetAutoIncrement(11 * time.Second)

		mockFeatureDetector := &environment.FakeFeatureDetector{
			Features: environment.Features{
				KernelSideRouteFiltering: true,
			},
		}

		config = &Config{
			Enabled:             true,
			ListeningPort:       51820,
			FirewallMark:        int(firewallMark),
			RoutingRulePriority: rulePriority,
			RoutingTableIndex:   tableIndex,
			InterfaceName:       "wg0",
			MTU:                 1420,
			EncryptHostTraffic:  false,
		}

		wg = NewWithShims(
			hostname,
			config,
			4,
			rtDataplane.NewMockNetlink,
			rrDataplane.NewMockNetlink,
			wgDataplane.NewMockNetlink,
			wgDataplane.NewMockWireguard,
			10*time.Second,
			t,
			routetable.FelixRouteProtocol,
			s.status,
			s.writeProcSys,
			logutils.NewSummarizer("test"),
			mockFeatureDetector,
		)
	})

	Context("when EncryptHostTraffic=false (default)", func() {
		Context("with single IP pool", func() {
			It("should create source-scoped routing rule for pod CIDR", func() {
				key_local := mustGeneratePrivateKey().PublicKey()
				wg.EndpointWireguardUpdate(hostname, key_local, nil)
				wg.EndpointUpdate(hostname, ipv4_local)
				wg.RouteUpdate(hostname, cidr_pool1)

				wg.OnIfaceStateChanged("wg0", 1, "up")
				err := wg.Apply()
				Expect(err).ToNot(HaveOccurred())

				Expect(rrDataplane.AddedRules).To(HaveLen(1))
				rule := rrDataplane.AddedRules[0]

				Expect(rule.Priority).To(Equal(rulePriority))
				Expect(rule.Table).To(Equal(tableIndex))
				Expect(rule.Invert).To(BeTrue())
				Expect(rule.Mark).To(Equal(firewallMark))
				Expect(rule.Mask).To(Equal(ptr.To(firewallMark)))
				Expect(rule.Src).ToNot(BeNil())
				Expect(rule.Src.String()).To(Equal(cidr_pool1.ToIPNet().String()))
			})
		})

		Context("with multiple IP pools", func() {
			It("should create source-scoped rules for each pod CIDR", func() {
				key_local := mustGeneratePrivateKey().PublicKey()
				wg.EndpointWireguardUpdate(hostname, key_local, nil)
				wg.EndpointUpdate(hostname, ipv4_local)
				wg.RouteUpdate(hostname, cidr_pool1)
				wg.RouteUpdate(hostname, cidr_pool2)

				wg.OnIfaceStateChanged("wg0", 1, "up")
				err := wg.Apply()
				Expect(err).ToNot(HaveOccurred())

				Expect(rrDataplane.AddedRules).To(HaveLen(2))

				srcCIDRs := make([]string, 0)
				for _, rule := range rrDataplane.AddedRules {
					Expect(rule.Priority).To(Equal(rulePriority))
					Expect(rule.Table).To(Equal(tableIndex))
					Expect(rule.Invert).To(BeTrue())
					Expect(rule.Mark).To(Equal(firewallMark))
					Expect(rule.Src).ToNot(BeNil())
					srcCIDRs = append(srcCIDRs, rule.Src.String())
				}

				Expect(srcCIDRs).To(ConsistOf(
					cidr_pool1.ToIPNet().String(),
					cidr_pool2.ToIPNet().String(),
				))
			})
		})

		Context("when IP pool is added dynamically", func() {
			It("should add new source-scoped rule", func() {
				key_local := mustGeneratePrivateKey().PublicKey()
				wg.EndpointWireguardUpdate(hostname, key_local, nil)
				wg.EndpointUpdate(hostname, ipv4_local)
				wg.RouteUpdate(hostname, cidr_pool1)

				wg.OnIfaceStateChanged("wg0", 1, "up")
				err := wg.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(rrDataplane.AddedRules).To(HaveLen(1))

				rrDataplane.ResetDeltas()

				wg.RouteUpdate(hostname, cidr_pool2)
				err = wg.Apply()
				Expect(err).ToNot(HaveOccurred())

				Expect(rrDataplane.DeletedRules).To(HaveLen(1))
				Expect(rrDataplane.AddedRules).To(HaveLen(2))

				srcCIDRs := make([]string, 0)
				for _, rule := range rrDataplane.AddedRules {
					Expect(rule.Src).ToNot(BeNil())
					srcCIDRs = append(srcCIDRs, rule.Src.String())
				}
				Expect(srcCIDRs).To(ConsistOf(
					cidr_pool1.ToIPNet().String(),
					cidr_pool2.ToIPNet().String(),
				))
			})
		})

		Context("when IP pool is removed", func() {
			It("should update source-scoped rules", func() {
				key_local := mustGeneratePrivateKey().PublicKey()
				wg.EndpointWireguardUpdate(hostname, key_local, nil)
				wg.EndpointUpdate(hostname, ipv4_local)
				wg.RouteUpdate(hostname, cidr_pool1)
				wg.RouteUpdate(hostname, cidr_pool2)

				wg.OnIfaceStateChanged("wg0", 1, "up")
				err := wg.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(rrDataplane.AddedRules).To(HaveLen(2))

				rrDataplane.ResetDeltas()

				wg.RouteRemove(cidr_pool2)
				err = wg.Apply()
				Expect(err).ToNot(HaveOccurred())

				Expect(rrDataplane.DeletedRules).To(HaveLen(2))
				Expect(rrDataplane.AddedRules).To(HaveLen(1))

				rule := rrDataplane.AddedRules[0]
				Expect(rule.Src).ToNot(BeNil())
				Expect(rule.Src.String()).To(Equal(cidr_pool1.ToIPNet().String()))
			})
		})

		Context("with /32 workload IPs", func() {
			It("should not create rules for individual IPs, only for CIDRs", func() {
				key_local := mustGeneratePrivateKey().PublicKey()
				wg.EndpointWireguardUpdate(hostname, key_local, nil)
				wg.EndpointUpdate(hostname, ipv4_local)
				wg.RouteUpdate(hostname, cidr_pool1)
				wg.RouteUpdate(hostname, cidr_workload)

				wg.OnIfaceStateChanged("wg0", 1, "up")
				err := wg.Apply()
				Expect(err).ToNot(HaveOccurred())

				Expect(rrDataplane.AddedRules).To(HaveLen(1))
				rule := rrDataplane.AddedRules[0]
				Expect(rule.Src.String()).To(Equal(cidr_pool1.ToIPNet().String()))
			})
		})
	})

	Context("when EncryptHostTraffic=true", func() {
		BeforeEach(func() {
			config.EncryptHostTraffic = true
			wg = NewWithShims(
				hostname,
				config,
				4,
				rtDataplane.NewMockNetlink,
				rrDataplane.NewMockNetlink,
				wgDataplane.NewMockNetlink,
				wgDataplane.NewMockWireguard,
				10*time.Second,
				t,
				routetable.FelixRouteProtocol,
				s.status,
				s.writeProcSys,
				logutils.NewSummarizer("test"),
				&environment.FakeFeatureDetector{
					Features: environment.Features{
						KernelSideRouteFiltering: true,
					},
				},
			)
		})

		It("should create single unscoped routing rule without source match", func() {
			key_local := mustGeneratePrivateKey().PublicKey()
			wg.EndpointWireguardUpdate(hostname, key_local, nil)
			wg.EndpointUpdate(hostname, ipv4_local)
			wg.RouteUpdate(hostname, cidr_pool1)

			wg.OnIfaceStateChanged("wg0", 1, "up")
			err := wg.Apply()
			Expect(err).ToNot(HaveOccurred())

			Expect(rrDataplane.AddedRules).To(HaveLen(1))
			rule := rrDataplane.AddedRules[0]

			Expect(rule.Priority).To(Equal(rulePriority))
			Expect(rule.Table).To(Equal(tableIndex))
			Expect(rule.Invert).To(BeTrue())
			Expect(rule.Mark).To(Equal(firewallMark))
			Expect(rule.Mask).To(Equal(ptr.To(firewallMark)))
			Expect(rule.Src).To(BeNil())
		})

		It("should not change rules when IP pools are added", func() {
			key_local := mustGeneratePrivateKey().PublicKey()
			wg.EndpointWireguardUpdate(hostname, key_local, nil)
			wg.EndpointUpdate(hostname, ipv4_local)
			wg.RouteUpdate(hostname, cidr_pool1)

			wg.OnIfaceStateChanged("wg0", 1, "up")
			err := wg.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(rrDataplane.AddedRules).To(HaveLen(1))
			Expect(rrDataplane.AddedRules[0].Src).To(BeNil())

			rrDataplane.ResetDeltas()

			wg.RouteUpdate(hostname, cidr_pool2)
			err = wg.Apply()
			Expect(err).ToNot(HaveOccurred())

			Expect(rrDataplane.AddedRules).To(HaveLen(0))
			Expect(rrDataplane.DeletedRules).To(HaveLen(0))
		})
	})

	Context("regression: pod-to-pod encryption still works", func() {
		BeforeEach(func() {
			config.EncryptHostTraffic = false
		})

		It("should route pod traffic through WireGuard with source-scoped rules", func() {
			key_local := mustGeneratePrivateKey().PublicKey()
			key_peer1 := mustGeneratePrivateKey().PublicKey()

			wg.EndpointWireguardUpdate(hostname, key_local, nil)
			wg.EndpointUpdate(hostname, ipv4_local)
			wg.RouteUpdate(hostname, cidr_pool1)

			wg.EndpointWireguardUpdate(peer1, key_peer1, nil)
			wg.EndpointUpdate(peer1, ipv4_peer1)
			wg.RouteUpdate(peer1, cidr_pool2)

			wg.OnIfaceStateChanged("wg0", 1, "up")
			err := wg.Apply()
			Expect(err).ToNot(HaveOccurred())

			Expect(rrDataplane.AddedRules).To(HaveLen(1))
			rule := rrDataplane.AddedRules[0]

			Expect(rule.Src).ToNot(BeNil())
			Expect(rule.Src.String()).To(Equal(cidr_pool1.ToIPNet().String()))

			link := wgDataplane.NameToLink["wg0"]
			Expect(link).ToNot(BeNil())
			Expect(link.WireguardPeers).To(HaveLen(1))
		})
	})
})

type mockStatus struct {
	numStatusCallbacks int
	statusKey          wgtypes.Key
}

func (s *mockStatus) status(publicKey wgtypes.Key) error {
	s.numStatusCallbacks++
	s.statusKey = publicKey
	return nil
}

func (s *mockStatus) writeProcSys(path, value string) error {
	return nil
}

func mustGeneratePrivateKey() wgtypes.Key {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		panic(err)
	}
	return key
}
