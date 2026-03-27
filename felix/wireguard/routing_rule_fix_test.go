package wireguard_test

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"k8s.io/utils/ptr"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/logutils"
	mocknetlink "github.com/projectcalico/calico/felix/netlinkshim/mocknetlink"
	"github.com/projectcalico/calico/felix/timeshim/mocktime"
	. "github.com/projectcalico/calico/felix/wireguard"
)

var _ = Describe("Source-scoped routing rules fix (Issue #9751)", func() {
	var (
		wg            *Wireguard
		wgDataplane   *mocknetlink.MockNetlinkDataplane
		rtDataplane   *mocknetlink.MockNetlinkDataplane
		rrDataplane   *mocknetlink.MockNetlinkDataplane
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
			FelixRouteProtocol,
			s.status,
			s.writeProcSys,
			logutils.NewSummarizer("test"),
			mockFeatureDetector,
		)

		// Bootstrap: perform the initial Apply to create the wg0 link in the mock dataplane,
		// then signal the interface is up so subsequent Apply calls proceed past ErrWaitingForLink.
		wgDataplane.ImmediateLinkUp = true
		_ = wg.Apply() // creates the link
		rtDataplane.AddIface(101, "wg0", true, true)
		wg.OnIfaceStateChanged("wg0", 101, ifacemonitor.StateUp)
		_ = wg.Apply() // brings WireGuard key + config in sync
		// Clear any rules recorded during bootstrap
		rrDataplane.AddedRules = nil
		rrDataplane.DeletedRules = nil
	})

	Context("when EncryptHostTraffic=false (default)", func() {
		Context("with single IP pool", func() {
			It("should create source-scoped routing rule for pod CIDR", func() {
				key_local := mustGeneratePrivateKey().PublicKey()
				wg.EndpointWireguardUpdate(hostname, key_local, nil)
				wg.EndpointUpdate(hostname, ipv4_local)
				wg.RouteUpdate(hostname, cidr_pool1)

				err := wg.Apply()
				Expect(err).ToNot(HaveOccurred())

				Expect(rrDataplane.AddedRules).To(HaveLen(1))
				rule := rrDataplane.AddedRules[0]

				Expect(rule.Priority).To(Equal(rulePriority))
				Expect(rule.Table).To(Equal(tableIndex))
				Expect(rule.Invert).To(BeFalse())
				Expect(rule.Mark).To(Equal(uint32(0)))
				Expect(rule.Mask).To(Equal(ptr.To(firewallMark)))
				Expect(rule.Src).ToNot(BeNil())
				Expect(rule.Src.String()).To(Equal(cidr_pool1.String()))
			})
		})

		Context("with multiple IP pools", func() {
			It("should create source-scoped rules for each pod CIDR", func() {
				key_local := mustGeneratePrivateKey().PublicKey()
				wg.EndpointWireguardUpdate(hostname, key_local, nil)
				wg.EndpointUpdate(hostname, ipv4_local)
				wg.RouteUpdate(hostname, cidr_pool1)
				wg.RouteUpdate(hostname, cidr_pool2)

				err := wg.Apply()
				Expect(err).ToNot(HaveOccurred())

				Expect(rrDataplane.AddedRules).To(HaveLen(2))

				srcCIDRs := make([]string, 0)
				for _, rule := range rrDataplane.AddedRules {
					Expect(rule.Priority).To(Equal(rulePriority))
					Expect(rule.Table).To(Equal(tableIndex))
					Expect(rule.Invert).To(BeFalse())
					Expect(rule.Mark).To(Equal(uint32(0)))
					Expect(rule.Src).ToNot(BeNil())
					srcCIDRs = append(srcCIDRs, rule.Src.String())
				}

				Expect(srcCIDRs).To(ConsistOf(
					cidr_pool1.String(),
					cidr_pool2.String(),
				))
			})
		})

		Context("when IP pool is added dynamically", func() {
			It("should add new source-scoped rule", func() {
				key_local := mustGeneratePrivateKey().PublicKey()
				wg.EndpointWireguardUpdate(hostname, key_local, nil)
				wg.EndpointUpdate(hostname, ipv4_local)
				wg.RouteUpdate(hostname, cidr_pool1)

				err := wg.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(rrDataplane.AddedRules).To(HaveLen(1))

				rrDataplane.ResetDeltas()

				wg.RouteUpdate(hostname, cidr_pool2)
				err = wg.Apply()
				Expect(err).ToNot(HaveOccurred())

			// cidr_pool1 rule already exists, only cidr_pool2 is newly added
			Expect(rrDataplane.DeletedRules).To(HaveLen(0))
			Expect(rrDataplane.AddedRules).To(HaveLen(1))

			rule := rrDataplane.AddedRules[0]
			Expect(rule.Src).ToNot(BeNil())
			Expect(rule.Src.String()).To(Equal(cidr_pool2.String()))
			})
		})

		Context("when IP pool is removed", func() {
			It("should update source-scoped rules", func() {
				key_local := mustGeneratePrivateKey().PublicKey()
				wg.EndpointWireguardUpdate(hostname, key_local, nil)
				wg.EndpointUpdate(hostname, ipv4_local)
				wg.RouteUpdate(hostname, cidr_pool1)
				wg.RouteUpdate(hostname, cidr_pool2)

				err := wg.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(rrDataplane.AddedRules).To(HaveLen(2))

				rrDataplane.ResetDeltas()

				wg.RouteRemove(cidr_pool2)
				err = wg.Apply()
				Expect(err).ToNot(HaveOccurred())

			// cidr_pool2 rule deleted, cidr_pool1 rule already exists (not re-added)
			Expect(rrDataplane.DeletedRules).To(HaveLen(1))
			Expect(rrDataplane.AddedRules).To(HaveLen(0))

			deletedRule := rrDataplane.DeletedRules[0]
			Expect(deletedRule.Src).ToNot(BeNil())
			Expect(deletedRule.Src.String()).To(Equal(cidr_pool2.String()))
			})
		})

		Context("with /32 workload IPs", func() {
			It("should not create rules for individual IPs, only for CIDRs", func() {
				key_local := mustGeneratePrivateKey().PublicKey()
				wg.EndpointWireguardUpdate(hostname, key_local, nil)
				wg.EndpointUpdate(hostname, ipv4_local)
				wg.RouteUpdate(hostname, cidr_pool1)
				wg.RouteUpdate(hostname, cidr_workload)

				err := wg.Apply()
				Expect(err).ToNot(HaveOccurred())

				Expect(rrDataplane.AddedRules).To(HaveLen(1))
				rule := rrDataplane.AddedRules[0]
				Expect(rule.Src.String()).To(Equal(cidr_pool1.String()))
			})
		})
	})

	Context("when EncryptHostTraffic=true", func() {
		BeforeEach(func() {
			// Use fresh dataplanes to avoid conflict with the outer BeforeEach's open netlink connections.
			wgDataplane = mocknetlink.New()
			rtDataplane = mocknetlink.New()
			rrDataplane = mocknetlink.New()

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
				FelixRouteProtocol,
				s.status,
				s.writeProcSys,
				logutils.NewSummarizer("test"),
				&environment.FakeFeatureDetector{
					Features: environment.Features{
						KernelSideRouteFiltering: true,
					},
				},
			)
			wgDataplane.ImmediateLinkUp = true
			_ = wg.Apply()
			rtDataplane.AddIface(101, "wg0", true, true)
			wg.OnIfaceStateChanged("wg0", 101, ifacemonitor.StateUp)
			_ = wg.Apply()
		})

		It("should create single unscoped routing rule without source match", func() {
			key_local := mustGeneratePrivateKey().PublicKey()
			wg.EndpointWireguardUpdate(hostname, key_local, nil)
			wg.EndpointUpdate(hostname, ipv4_local)
			wg.RouteUpdate(hostname, cidr_pool1)

			err := wg.Apply()
			Expect(err).ToNot(HaveOccurred())

			// The unscoped rule is idempotent — it is set during bootstrap and remains.
			// Filter rrDataplane.Rules to find our wireguard routing rule by priority.
			wgRules := filterRulesByPriority(rrDataplane.Rules, rulePriority)
			Expect(wgRules).To(HaveLen(1))
			rule := wgRules[0]

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

			err := wg.Apply()
			Expect(err).ToNot(HaveOccurred())
			wgRules := filterRulesByPriority(rrDataplane.Rules, rulePriority)
			Expect(wgRules).To(HaveLen(1))
			Expect(wgRules[0].Src).To(BeNil())

			rrDataplane.ResetDeltas()

			wg.RouteUpdate(hostname, cidr_pool2)
			err = wg.Apply()
			Expect(err).ToNot(HaveOccurred())

			// No rules should be added or deleted — the unscoped rule is idempotent.
			Expect(rrDataplane.AddedRules).To(HaveLen(0))
			Expect(rrDataplane.DeletedRules).To(HaveLen(0))
			wgRules = filterRulesByPriority(rrDataplane.Rules, rulePriority)
			Expect(wgRules).To(HaveLen(1))
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

			err := wg.Apply()
			Expect(err).ToNot(HaveOccurred())

			Expect(rrDataplane.AddedRules).To(HaveLen(1))
			rule := rrDataplane.AddedRules[0]

			Expect(rule.Src).ToNot(BeNil())
			Expect(rule.Src.String()).To(Equal(cidr_pool1.String()))

			link := wgDataplane.NameToLink["wg0"]
			Expect(link).ToNot(BeNil())
			Expect(link.WireguardPeers).To(HaveLen(1))
		})

Context("when switching EncryptHostTraffic modes at runtime", func() {
It("should remove old unscoped rule when switching from true to false", func() {
// Start with EncryptHostTraffic=true
config.EncryptHostTraffic = true
key_local := mustGeneratePrivateKey().PublicKey()
wg.EndpointWireguardUpdate(hostname, key_local, nil)
wg.EndpointUpdate(hostname, ipv4_local)
wg.RouteUpdate(hostname, cidr_pool1)

err := wg.Apply()
Expect(err).ToNot(HaveOccurred())

// Verify unscoped rule was added
Expect(rrDataplane.AddedRules).To(HaveLen(1))
unscopedRule := rrDataplane.AddedRules[0]
Expect(unscopedRule.Src).To(BeNil()) // Unscoped

// Switch to EncryptHostTraffic=false
config.EncryptHostTraffic = false
rrDataplane.AddedRules = nil
rrDataplane.DeletedRules = nil

err = wg.Apply()
Expect(err).ToNot(HaveOccurred())

// Verify old unscoped rule was removed and per-CIDR rule was added
Expect(rrDataplane.DeletedRules).To(HaveLen(1))
deletedRule := rrDataplane.DeletedRules[0]
Expect(deletedRule.Src).To(BeNil()) // Unscoped rule deleted

Expect(rrDataplane.AddedRules).To(HaveLen(1))
newRule := rrDataplane.AddedRules[0]
Expect(newRule.Src).ToNot(BeNil())
Expect(newRule.Src.String()).To(Equal(cidr_pool1.String()))
})

It("should remove old per-CIDR rules when switching from false to true", func() {
// Start with EncryptHostTraffic=false
config.EncryptHostTraffic = false
key_local := mustGeneratePrivateKey().PublicKey()
wg.EndpointWireguardUpdate(hostname, key_local, nil)
wg.EndpointUpdate(hostname, ipv4_local)
wg.RouteUpdate(hostname, cidr_pool1)
wg.RouteUpdate(hostname, cidr_pool2)

err := wg.Apply()
Expect(err).ToNot(HaveOccurred())

// Verify per-CIDR rules were added
Expect(rrDataplane.AddedRules).To(HaveLen(2))
for _, rule := range rrDataplane.AddedRules {
Expect(rule.Src).ToNot(BeNil()) // Source-scoped
}

// Switch to EncryptHostTraffic=true
config.EncryptHostTraffic = true
rrDataplane.AddedRules = nil
rrDataplane.DeletedRules = nil

err = wg.Apply()
Expect(err).ToNot(HaveOccurred())

// Verify old per-CIDR rules were removed and unscoped rule was added
Expect(rrDataplane.DeletedRules).To(HaveLen(2))
for _, rule := range rrDataplane.DeletedRules {
Expect(rule.Src).ToNot(BeNil()) // Per-CIDR rules deleted
}

Expect(rrDataplane.AddedRules).To(HaveLen(1))
newRule := rrDataplane.AddedRules[0]
Expect(newRule.Src).To(BeNil()) // Unscoped
})
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

// filterRulesByPriority returns only the rules with the given priority,
// filtering out default kernel rules (priority 0, 32766, 32767).
func filterRulesByPriority(rules []netlink.Rule, priority int) []netlink.Rule {
	var out []netlink.Rule
	for _, r := range rules {
		if r.Priority == priority {
			out = append(out, r)
		}
	}
	return out
}
