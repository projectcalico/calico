// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package intdataplane

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	dpsets "github.com/projectcalico/calico/felix/dataplane/ipsets"
	"github.com/projectcalico/calico/felix/dataplane/linux/dataplanedefs"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/netlinkshim/mocknetlink"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/lib/logrusr"
)

var _ = Describe("Route manager", func() {
	var (
		rt        *mockRouteTable
		dataplane *mocknetlink.MockNetlinkDataplane
		dpConfig  Config
		routeMgr  *routeManager
	)

	BeforeEach(func() {
		rt = &mockRouteTable{
			currentRoutes: map[string][]routetable.Target{},
		}

		dataplane = mocknetlink.New()
		_, err := dataplane.NewMockNetlink()
		Expect(err).NotTo(HaveOccurred())
		eth0 := dataplane.AddIface(2, "eth0", true, true)
		Expect(dataplane.AddrAdd(eth0, &netlink.Addr{IPNet: &net.IPNet{IP: net.IPv4(172, 0, 0, 2)}})).To(Succeed())
		dataplane.ResetDeltas()

		dpConfig = Config{
			Hostname:             "node1",
			MaxIPSetSize:         5,
			ProgramClusterRoutes: true,
		}

		routeMgr = newRouteManager(
			rt,
			routetable.RouteClassVXLANTunnel,
			routetable.RouteClassVXLANSameSubnet,
			proto.IPPoolType_VXLAN,
			dataplanedefs.VXLANIfaceNameV4,
			4,
			1400,
			dpConfig,
			logrusr.NewSummarizer("test"),
			dataplane,
		)
		routeMgr.setTunnelRouteFunc(func(cidr ip.CIDR, r *proto.RouteUpdate) *routetable.Target {
			return &routetable.Target{
				Type:     routetable.TargetTypeVXLAN,
				RouteKey: routetable.RouteKey{CIDR: cidr},
				GW:       ip.FromString("10.0.0.1"),
			}
		})
	})

	Describe("with VXLAN, IPIP and no-encap managers sharing one route table", func() {
		// This mirrors the way int_dataplane wires the managers up: they all
		// program the same main route table, and they all see every route update.
		var managers []Manager

		localBlock := func(poolType proto.IPPoolType, dst string) *proto.RouteUpdate {
			return &proto.RouteUpdate{
				Types:       proto.RouteType_LOCAL_WORKLOAD,
				IpPoolType:  poolType,
				Dst:         dst,
				DstNodeName: "node1",
			}
		}

		BeforeEach(func() {
			vxlanMgr := newVXLANManagerWithShims(
				dpsets.NewMockIPSets(),
				rt,
				&mockVXLANFDB{},
				dataplanedefs.VXLANIfaceNameV4,
				4,
				1400,
				dpConfig,
				logrusr.NewSummarizer("test"),
				dataplane,
			)
			ipipMgr := newIPIPManagerWithShims(
				rt,
				dataplanedefs.IPIPIfaceName,
				4,
				1400,
				dpConfig,
				logrusr.NewSummarizer("test"),
				dataplane,
			)
			noEncapMgr := newNoEncapManagerWithSims(
				rt,
				4,
				dpConfig,
				logrusr.NewSummarizer("test"),
				dataplane,
			)
			managers = []Manager{vxlanMgr, ipipMgr, noEncapMgr}

			// Each manager gets a local IPAM block from each type of pool; it
			// should only program a blackhole route for the block that belongs
			// to its own type of pool.
			for _, m := range managers {
				m.OnUpdate(localBlock(proto.IPPoolType_VXLAN, "10.0.1.0/26"))
				m.OnUpdate(localBlock(proto.IPPoolType_IPIP, "10.0.2.0/26"))
				m.OnUpdate(localBlock(proto.IPPoolType_NO_ENCAP, "10.0.3.0/26"))
			}
			for _, m := range managers {
				Expect(m.CompleteDeferredWork()).To(Succeed())
			}
		})

		It("should keep the blackhole routes of every manager", func() {
			// Each manager owns its own route class, so no manager's SetRoutes
			// call can delete another manager's blackhole routes.
			Expect(rt.cidrsForClass(routetable.RouteClassBlackholeVXLAN, routetable.InterfaceNone)).To(
				ConsistOf("10.0.1.0/26"))
			Expect(rt.cidrsForClass(routetable.RouteClassBlackholeIPIP, routetable.InterfaceNone)).To(
				ConsistOf("10.0.2.0/26"))
			Expect(rt.cidrsForClass(routetable.RouteClassBlackholeNoEncap, routetable.InterfaceNone)).To(
				ConsistOf("10.0.3.0/26"))
		})

		It("should remove only its own blackhole routes when a block goes away", func() {
			for _, m := range managers {
				m.OnUpdate(&proto.RouteRemove{Dst: "10.0.2.0/26"})
			}
			for _, m := range managers {
				Expect(m.CompleteDeferredWork()).To(Succeed())
			}

			Expect(rt.cidrsForClass(routetable.RouteClassBlackholeIPIP, routetable.InterfaceNone)).To(BeEmpty())
			Expect(rt.cidrsForClass(routetable.RouteClassBlackholeVXLAN, routetable.InterfaceNone)).To(
				ConsistOf("10.0.1.0/26"))
			Expect(rt.cidrsForClass(routetable.RouteClassBlackholeNoEncap, routetable.InterfaceNone)).To(
				ConsistOf("10.0.3.0/26"))
		})
	})

	Describe("parent interface address updates", func() {
		// The device-sync goroutine drains tunnelChangedC and takes
		// parentDeviceLock itself, so updateParentIfaceAddr must not block while
		// holding that lock: if it did, back-to-back updates from the dataplane
		// main loop would deadlock against the goroutine.
		It("should not block when the device-sync goroutine hasn't drained the channel", func() {
			routeMgr.updateParentIfaceAddr("172.0.0.2")

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done)
				routeMgr.updateParentIfaceAddr("172.0.0.3")
			}()
			Eventually(done).Should(BeClosed())

			// ...and the lock must be free for the device-sync goroutine.
			addrRead := make(chan string)
			go func() {
				defer GinkgoRecover()
				addrRead <- routeMgr.parentIfaceAddr()
			}()
			Eventually(addrRead).Should(Receive(Equal("172.0.0.3")))
		})

		It("should kick the device-sync goroutine", func() {
			routeMgr.updateParentIfaceAddr("172.0.0.2")
			Expect(routeMgr.tunnelChangedC).To(Receive())
			Expect(routeMgr.parentIfaceAddr()).To(Equal("172.0.0.2"))
		})
	})

	Describe("tunnel device sync retries", func() {
		// Each failed attempt costs a netlink LinkList plus an AddrList per
		// link, and the commonest failure — a host address that isn't on any
		// local link — is permanent.  Retrying that once a second forever is
		// both a netlink load and a stream of warnings, so the delay grows.
		It("should back off up to the healthy poll interval", func() {
			delay := tunnelSyncMinRetryDelay
			delays := []time.Duration{delay}
			for range 5 {
				delay = nextTunnelSyncRetryDelay(delay, 10*time.Second)
				delays = append(delays, delay)
			}
			Expect(delays).To(Equal([]time.Duration{
				1 * time.Second,
				2 * time.Second,
				4 * time.Second,
				8 * time.Second,
				10 * time.Second,
				10 * time.Second,
			}))
		})

		// The loop polls every "wait" once it is healthy; retrying a failure
		// less often than that would leave the device unconfigured for longer
		// than a working node goes unchecked.
		It("should not back off beyond the poll interval", func() {
			Expect(nextTunnelSyncRetryDelay(10*time.Second, 10*time.Second)).
				To(Equal(10 * time.Second))
		})

		// A caller with a short (or unset) poll interval must not end up
		// spinning: the minimum delay wins over the cap.
		It("should not retry faster than the minimum delay", func() {
			Expect(nextTunnelSyncRetryDelay(tunnelSyncMinRetryDelay, 0)).
				To(Equal(tunnelSyncMinRetryDelay))
			Expect(nextTunnelSyncRetryDelay(tunnelSyncMinRetryDelay, 100*time.Millisecond)).
				To(Equal(tunnelSyncMinRetryDelay))
		})
	})

	Describe("tunnel device sync recovery reporting", func() {
		// "Tunnel device configured" is how an operator sees that the device
		// came back, and the failure logs around it are rate limited, so every
		// path that leaves the device unconfigured has to arm it.  Losing the
		// host address is one of those paths: it is what takes the parent
		// device away in the first place.
		It("should report the recovery after the host address comes back", func() {
			logs := captureStandardLogs()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Buffered so that the loop's parent-device notification doesn't
			// block it; it only sends when the device name changes.
			parentIfaceC := make(chan string, 10)
			routeMgr.updateParentIfaceAddr("172.0.0.2")

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done)
				routeMgr.keepDeviceInSync(ctx, 1400, false, 10*time.Second, parentIfaceC,
					func(netlink.Link) (netlink.Link, string, error) {
						// A nil link means "nothing to configure", which takes
						// the loop straight to its success bookkeeping.
						return nil, "", nil
					})
			}()

			configured := logs.counter("Tunnel device configured")
			Eventually(configured).Should(Equal(1))

			// Take the address away, and wait for the loop to notice before
			// giving it back: it is that iteration which has to arm the log.
			routeMgr.updateParentIfaceAddr("")
			Eventually(logs.counter("Missing local information, retrying...")).
				Should(BeNumerically(">=", 1))
			Expect(configured()).To(Equal(1))

			routeMgr.updateParentIfaceAddr("172.0.0.2")
			Eventually(configured).Should(Equal(2))

			cancel()
			Eventually(done).Should(BeClosed())
		})
	})

	Describe("parent device updates", func() {
		BeforeEach(func() {
			routeMgr.OnParentDeviceUpdate("eth0")
			routeMgr.OnUpdate(&proto.RouteUpdate{
				Types:       proto.RouteType_REMOTE_WORKLOAD,
				IpPoolType:  proto.IPPoolType_VXLAN,
				Dst:         "10.0.1.0/26",
				DstNodeName: "node2",
				DstNodeIp:   "172.0.0.3",
				SameSubnet:  true,
			})
			Expect(routeMgr.CompleteDeferredWork()).To(Succeed())
			Expect(rt.cidrsForClass(routetable.RouteClassVXLANSameSubnet, "eth0")).To(
				ConsistOf("10.0.1.0/26"))
		})

		// No caller has a use for an empty parent device name; treating it as a
		// device change would tear down the same-subnet routes of the device we
		// are actually using.
		It("should ignore an empty parent device name", func() {
			Expect(routeMgr.OnParentDeviceUpdate("")).To(BeFalse())

			Expect(routeMgr.parentDevice).To(Equal("eth0"))
			Expect(rt.cidrsForClass(routetable.RouteClassVXLANSameSubnet, "eth0")).To(
				ConsistOf("10.0.1.0/26"))
		})

		It("should move the same-subnet routes when the parent device changes", func() {
			Expect(routeMgr.OnParentDeviceUpdate("eth1")).To(BeTrue())
			Expect(routeMgr.CompleteDeferredWork()).To(Succeed())

			Expect(rt.cidrsForClass(routetable.RouteClassVXLANSameSubnet, "eth0")).To(BeEmpty())
			Expect(rt.cidrsForClass(routetable.RouteClassVXLANSameSubnet, "eth1")).To(
				ConsistOf("10.0.1.0/26"))
		})
	})

	Describe("local IPAM block classification", func() {
		// CIDRFromString returns a nil CIDR alongside its error, so a route with
		// an unparseable destination must not reach the CIDR-dependent checks.
		It("should not panic on a route with an unparseable destination", func() {
			Expect(routeMgr.routeIsLocalBlock(&proto.RouteUpdate{
				Types:      proto.RouteType_LOCAL_WORKLOAD,
				IpPoolType: proto.IPPoolType_VXLAN,
				Dst:        "not-a-cidr",
			})).To(BeFalse())
		})

		It("should treat a block CIDR as a local block but not an exact route", func() {
			Expect(routeMgr.routeIsLocalBlock(&proto.RouteUpdate{
				Types:      proto.RouteType_LOCAL_WORKLOAD,
				IpPoolType: proto.IPPoolType_VXLAN,
				Dst:        "10.0.1.0/26",
			})).To(BeTrue())
			Expect(routeMgr.routeIsLocalBlock(&proto.RouteUpdate{
				Types:      proto.RouteType_LOCAL_WORKLOAD,
				IpPoolType: proto.IPPoolType_VXLAN,
				Dst:        "10.0.1.1/32",
			})).To(BeFalse())
		})
	})
})

// captureStandardLogs collects the messages logged to the standard logger for
// the rest of the spec.  keepDeviceInSync builds its own rate-limited logger on
// top of that logger, so a hook is the only way to see what it reports.
func captureStandardLogs() *logCapture {
	logger := logrus.StandardLogger()
	capture := &logCapture{}

	oldHooks := logger.ReplaceHooks(logrus.LevelHooks{})
	logger.AddHook(capture)
	// The loop reports the loss of the host address at debug level, and the
	// output would otherwise clutter the spec's report.
	oldLevel, oldOut := logger.GetLevel(), logger.Out
	logger.SetLevel(logrus.DebugLevel)
	logger.SetOutput(io.Discard)

	DeferCleanup(func() {
		logger.ReplaceHooks(oldHooks)
		logger.SetLevel(oldLevel)
		logger.SetOutput(oldOut)
	})

	return capture
}

// logCapture is a logrus hook that records the messages it is given.
type logCapture struct {
	lock     sync.Mutex
	messages []string
}

func (c *logCapture) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (c *logCapture) Fire(entry *logrus.Entry) error {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.messages = append(c.messages, entry.Message)
	return nil
}

// counter returns how many times the message has been logged so far, as a
// function so that it can be polled by Eventually.
func (c *logCapture) counter(message string) func() int {
	return func() int {
		c.lock.Lock()
		defer c.lock.Unlock()
		count := 0
		for _, m := range c.messages {
			if m == message {
				count++
			}
		}
		return count
	}
}
