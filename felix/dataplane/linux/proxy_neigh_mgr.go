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
	"errors"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mdlayher/arp"
	"github.com/mdlayher/ethernet"
	"github.com/mdlayher/ndp"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/ipv6"
	v1 "k8s.io/api/core/v1"

	"github.com/projectcalico/calico/felix/netlinkshim"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/lib/datastructures/hashring"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// readDeadlineInterval bounds how long an ARP/NDP listener blocks in a
// single socket read before waking to re-check for context cancellation.
// A read that hits the deadline simply loops
const readDeadlineInterval = 1 * time.Second

// ipv6AllNodesMulticast is the IPv6 all-nodes link-local multicast address
const ipv6AllNodesMulticast = "ff02::1"

// serviceID identifies a Kubernetes Service by namespace and name. Used as a
// map key for tracking LoadBalancer service IPs.
type serviceID struct {
	Namespace string
	Name      string
}

// arpClient abstracts the mdlayher/arp.Client for testing.
type arpClient interface {
	Read() (*arp.Packet, *ethernet.Frame, error)
	Reply(*arp.Packet, net.HardwareAddr, netip.Addr) error
	WriteTo(*arp.Packet, net.HardwareAddr) error
	SetReadDeadline(time.Time) error
	Close() error
}

// ndpConn abstracts the mdlayher/ndp.Conn for testing.
type ndpConn interface {
	ReadFrom() (ndp.Message, *ipv6.ControlMessage, netip.Addr, error)
	WriteTo(ndp.Message, *ipv6.ControlMessage, netip.Addr) error
	SetReadDeadline(time.Time) error
	Close() error
}

type arpClientFactory func(ifaceName string) (arpClient, net.HardwareAddr, error)
type ndpConnFactory func(ifaceName string) (ndpConn, net.HardwareAddr, error)

// proxyNeighManager automatically responds to ARP (IPv4) and NDP (IPv6) requests for
// pod and LoadBalancer IPs that fall within the same L2 subnet as a host interface.
// It listens on raw sockets and responds directly in userspace.
type proxyNeighManager struct {
	ipVersion      uint8
	hostname       string
	wlIfacesRegexp *regexp.Regexp

	// readTimeout bounds how long each listener blocks in a single socket read
	// before looping to re-check for cancellation.
	readTimeout time.Duration

	// hostIfaceToCIDRs maps host interface name to the parsed CIDRs on that interface.
	hostIfaceToCIDRs map[string][]net.IPNet

	// localWorkloadIPs maps workload endpoint ID to the pod's IP strings.
	localWorkloadIPs map[types.WorkloadEndpointID][]string

	// lbServiceIPs maps service ID to LoadBalancer ingress IP strings.
	lbServiceIPs map[serviceID][]string

	// nodeRing is a consistent hash ring of the cluster's hostnames, used to
	// pick the single node that answers ARP/NDP for each LoadBalancer VIP.
	nodeRing *hashring.Ring[string]

	// noEncapPools maps IPPool ID to the pool's parsed CIDR.
	noEncapPools map[string]net.IPNet

	// listeners maps interface name to its active raw socket listener.
	listeners map[string]*ifaceListener

	dirty    bool
	nlHandle netlinkshim.Interface

	arpFactory arpClientFactory
	ndpFactory ndpConnFactory

	ctx    context.Context
	cancel context.CancelFunc
}

func newProxyNeighManager(dpConfig Config, ipVersion uint8) *proxyNeighManager {
	nl, err := netlinkshim.NewRealNetlink()
	if err != nil {
		logrus.WithError(err).Error("Failed to create netlink handle for proxy neighbor manager")
	}
	var af arpClientFactory
	var nf ndpConnFactory
	if ipVersion == 4 {
		af = func(ifaceName string) (arpClient, net.HardwareAddr, error) {
			ifi, err := net.InterfaceByName(ifaceName)
			if err != nil {
				return nil, nil, err
			}
			c, err := arp.Dial(ifi)
			if err != nil {
				return nil, nil, err
			}
			return c, ifi.HardwareAddr, nil
		}
	} else {
		nf = func(ifaceName string) (ndpConn, net.HardwareAddr, error) {
			ifi, err := net.InterfaceByName(ifaceName)
			if err != nil {
				return nil, nil, err
			}
			conn, _, err := ndp.Listen(ifi, ndp.Unspecified)
			if err != nil {
				return nil, nil, err
			}
			// Set the ICMPV6 filter to only deliver Neighbor Solicitations
			var f ipv6.ICMPFilter
			f.SetAll(true)
			f.Accept(ipv6.ICMPTypeNeighborSolicitation)
			if err := conn.SetICMPFilter(&f); err != nil {
				_ = conn.Close()
				return nil, nil, err
			}
			return conn, ifi.HardwareAddr, nil
		}
	}
	return newProxyNeighManagerWithShims(dpConfig, ipVersion, nl, af, nf, readDeadlineInterval)
}

func newProxyNeighManagerWithShims(
	dpConfig Config,
	ipVersion uint8,
	nl netlinkshim.Interface,
	af arpClientFactory,
	nf ndpConnFactory,
	readTimeout time.Duration,
) *proxyNeighManager {
	wlIfacesPattern := "^(" + strings.Join(dpConfig.RulesConfig.WorkloadIfacePrefixes, "|") + ").*"
	wlIfacesRegexp := regexp.MustCompile(wlIfacesPattern)

	ctx, cancel := context.WithCancel(context.Background())
	return &proxyNeighManager{
		ipVersion:        ipVersion,
		hostname:         dpConfig.Hostname,
		wlIfacesRegexp:   wlIfacesRegexp,
		readTimeout:      readTimeout,
		hostIfaceToCIDRs: make(map[string][]net.IPNet),
		localWorkloadIPs: make(map[types.WorkloadEndpointID][]string),
		lbServiceIPs:     make(map[serviceID][]string),
		nodeRing:         hashring.New[string](hashring.WithReplicas(100)),
		noEncapPools:     make(map[string]net.IPNet),
		listeners:        make(map[string]*ifaceListener),
		nlHandle:         nl,
		arpFactory:       af,
		ndpFactory:       nf,
		ctx:              ctx,
		cancel:           cancel,
	}
}

func (m *proxyNeighManager) OnUpdate(protoBufMsg any) {
	switch msg := protoBufMsg.(type) {
	case *ifaceAddrsUpdate:
		if m.wlIfacesRegexp.MatchString(msg.Name) {
			logrus.WithFields(logrus.Fields{
				"ifaceName": msg.Name,
			}).Debug("Ignoring ifaceAddrsUpdate for workload interface")
			return
		}
		logrus.WithFields(logrus.Fields{
			"ifaceName": msg.Name,
			"addrs":     msg.Addrs,
		}).Debug("Proxy neighbor manager received ifaceAddrsUpdate")
		if msg.Addrs == nil {
			delete(m.hostIfaceToCIDRs, msg.Name)
		} else {
			m.refreshHostIface(msg.Name)
		}
		m.dirty = true

	case *proto.WorkloadEndpointUpdate:
		ep := msg.GetEndpoint()
		if ep == nil || msg.GetId() == nil {
			return
		}
		wlKey := types.ProtoToWorkloadEndpointID(msg.GetId())
		var ips []string
		if m.ipVersion == 4 {
			ips = ep.Ipv4Nets
		} else {
			ips = ep.Ipv6Nets
		}
		logrus.WithFields(logrus.Fields{
			"workload":      wlKey,
			"ips":           ips,
			"migrationRole": ep.LiveMigrationRole,
		}).Debug("Proxy neighbor manager received WorkloadEndpointUpdate")
		if ep.LiveMigrationRole != proto.LiveMigrationRole_SOURCE && len(ips) > 0 {
			m.localWorkloadIPs[wlKey] = ips
		} else {
			delete(m.localWorkloadIPs, wlKey)
		}
		m.dirty = true

	case *proto.WorkloadEndpointRemove:
		if msg.GetId() == nil {
			return
		}
		wlKey := types.ProtoToWorkloadEndpointID(msg.GetId())
		if _, ok := m.localWorkloadIPs[wlKey]; ok {
			logrus.WithField("workload", wlKey).Debug("Proxy neighbor manager received WorkloadEndpointRemove")
			delete(m.localWorkloadIPs, wlKey)
			m.dirty = true
		}

	case *proto.ServiceUpdate:
		svcKey := serviceID{Namespace: msg.Namespace, Name: msg.Name}
		if v1.ServiceType(msg.Type) != v1.ServiceTypeLoadBalancer {
			if _, ok := m.lbServiceIPs[svcKey]; ok {
				delete(m.lbServiceIPs, svcKey)
				m.dirty = true
			}
			return
		}
		var lbIPs []string
		for _, ipStr := range msg.LoadbalancerIngressIps {
			if m.isMatchingIPVersion(ipStr) {
				lbIPs = append(lbIPs, ipStr)
			}
		}
		if msg.LoadbalancerIp != "" && m.isMatchingIPVersion(msg.LoadbalancerIp) {
			lbIPs = append(lbIPs, msg.LoadbalancerIp)
		}
		logrus.WithFields(logrus.Fields{
			"service": svcKey,
			"lbIPs":   lbIPs,
		}).Debug("Proxy neighbor manager received ServiceUpdate")
		if len(lbIPs) > 0 {
			m.lbServiceIPs[svcKey] = lbIPs
			m.dirty = true
		} else if _, ok := m.lbServiceIPs[svcKey]; ok {
			delete(m.lbServiceIPs, svcKey)
			m.dirty = true
		}

	case *proto.ServiceRemove:
		svcKey := serviceID{Namespace: msg.Namespace, Name: msg.Name}
		if _, ok := m.lbServiceIPs[svcKey]; ok {
			logrus.WithField("service", svcKey).Debug("Proxy neighbor manager received ServiceRemove")
			delete(m.lbServiceIPs, svcKey)
			m.dirty = true
		}

	case *proto.HostMetadataUpdate:
		// Skip nodes that have no address for this manager's IP version —
		// they can't host pods/VIPs in our family, so they shouldn't be in
		// the hash ring.
		addr := msg.Ipv4Addr
		if m.ipVersion == 6 {
			addr = msg.Ipv6Addr
		}
		if addr == "" {
			return
		}
		before := m.nodeRing.Len()
		m.nodeRing.Insert(msg.Hostname, msg.Hostname)
		if m.nodeRing.Len() != before {
			logrus.WithField("hostname", msg.Hostname).Debug("Proxy neighbor manager received HostMetadataUpdate")
			m.dirty = true
		}

	case *proto.HostMetadataRemove:
		before := m.nodeRing.Len()
		m.nodeRing.Remove(msg.Hostname)
		if m.nodeRing.Len() != before {
			logrus.WithField("hostname", msg.Hostname).Debug("Proxy neighbor manager received HostMetadataRemove")
			m.dirty = true
		}

	case *proto.IPAMPoolUpdate:
		pool := msg.GetPool()
		if pool == nil {
			return
		}
		if isNoEncapPool(pool) {
			_, cidr, err := net.ParseCIDR(pool.Cidr)
			if err != nil {
				logrus.WithError(err).WithField("cidr", pool.Cidr).Warn("Failed to parse IPPool CIDR")
				return
			}
			logrus.WithFields(logrus.Fields{
				"poolID": msg.Id,
				"cidr":   pool.Cidr,
			}).Debug("Proxy neighbor manager tracking no-encap IPPool")
			m.noEncapPools[msg.Id] = *cidr
		} else {
			delete(m.noEncapPools, msg.Id)
		}
		m.dirty = true

	case *proto.IPAMPoolRemove:
		if _, ok := m.noEncapPools[msg.Id]; ok {
			logrus.WithField("poolID", msg.Id).Debug("Proxy neighbor manager received IPAMPoolRemove")
			delete(m.noEncapPools, msg.Id)
			m.dirty = true
		}
	}
}

func (m *proxyNeighManager) CompleteDeferredWork() error {
	if !m.dirty && !m.hasFailedListener() {
		return nil
	}
	m.dirty = false

	logrus.WithFields(logrus.Fields{
		"numWorkloads":  len(m.localWorkloadIPs),
		"numHostIfaces": len(m.hostIfaceToCIDRs),
		"numLBServices": len(m.lbServiceIPs),
		"numNodes":      m.nodeRing.Len(),
	}).Debug("Proxy neighbor manager CompleteDeferredWork")

	desiredByIface := m.buildDesiredState()
	err := m.reconcileListeners(desiredByIface)
	m.publishDesiredIPs(desiredByIface)

	return err
}

// Stop tears down every listener (cancelling its goroutine and closing its raw
// socket) and cancels the manager's context. Used for clean shutdown by tests
func (m *proxyNeighManager) Stop() {
	for ifaceName, l := range m.listeners {
		l.stop()
		delete(m.listeners, ifaceName)
	}
	m.cancel()
}

// hasFailedListener reports whether any listener goroutine has flagged itself
// failed (and so needs dropping and recreating by reconcileListeners).
func (m *proxyNeighManager) hasFailedListener() bool {
	for _, l := range m.listeners {
		if l.failed.Load() {
			return true
		}
	}
	return false
}

// buildDesiredState computes which IPs each host interface should answer for:
// the node's own pod IPs, plus any LoadBalancer VIPs this node was selected to
// own. Only IPs that fall in a no-encap pool and within a host interface's
// subnet are included.
func (m *proxyNeighManager) buildDesiredState() map[string]set.Set[string] {
	desiredByIface := make(map[string]set.Set[string])

	// Pod IPs: the hosting node always answers for its own pods.
	for _, ipNets := range m.localWorkloadIPs {
		for _, ipNet := range ipNets {
			podIP, _, err := net.ParseCIDR(ipNet)
			if err != nil {
				continue
			}
			if !m.isInNoEncapPool(podIP) {
				continue
			}
			m.addMatchingIPs(desiredByIface, podIP)
		}
	}

	// LoadBalancer IPs: hash-based node selection picks one node per IP.
	for _, lbIPs := range m.lbServiceIPs {
		for _, ipStr := range lbIPs {
			if !m.selectNodeForIP(ipStr) {
				continue
			}
			lbIP := net.ParseIP(ipStr)
			if lbIP == nil {
				continue
			}
			if !m.isInNoEncapPool(lbIP) {
				continue
			}
			m.addMatchingIPs(desiredByIface, lbIP)
		}
	}

	return desiredByIface
}

// addMatchingIPs adds the IP to the desired set for every host interface whose subnet
// contains it.
func (m *proxyNeighManager) addMatchingIPs(desiredByIface map[string]set.Set[string], ip net.IP) {
	for ifaceName, cidrs := range m.hostIfaceToCIDRs {
		for _, cidr := range cidrs {
			if cidr.Contains(ip) {
				if desiredByIface[ifaceName] == nil {
					desiredByIface[ifaceName] = set.New[string]()
				}
				desiredByIface[ifaceName].Add(ip.String())
				break
			}
		}
	}
}

// reconcileListeners drops listeners that are no longer desired or have failed,
// then starts one for each desired interface that has no listener, which
// recreates any failed listener just dropped.
func (m *proxyNeighManager) reconcileListeners(desiredByIface map[string]set.Set[string]) error {
	// Drop listeners that are no longer desired or whose goroutine reported an
	// unrecoverable socket error.
	for ifaceName, l := range m.listeners {
		if _, desired := desiredByIface[ifaceName]; desired && !l.failed.Load() {
			continue
		}
		l.stop()
		delete(m.listeners, ifaceName)
	}
	// Start a listener for each desired interface that doesn't have one (this
	// recreates any failed listener dropped above).
	var err error
	for ifaceName := range desiredByIface {
		if _, ok := m.listeners[ifaceName]; !ok {
			if err = m.startListener(ifaceName); err != nil {
				logrus.WithError(err).WithField("iface", ifaceName).Warn("Failed to start listener; will retry")
				// Re-mark dirty so the next CompleteDeferredWork retries,
				// and remember the error to surface it to the dataplane loop.
				m.dirty = true
			}
		}
	}
	return err
}

// publishDesiredIPs atomically swaps each listener's desired IP set and sends a
// gratuitous ARP (IPv4) / unsolicited NA (IPv6) for every IP that is newly
// appearing on that interface.
func (m *proxyNeighManager) publishDesiredIPs(desiredByIface map[string]set.Set[string]) {
	for ifaceName, desired := range desiredByIface {
		l, ok := m.listeners[ifaceName]
		if !ok {
			continue
		}
		// Atomically swap in the new desired set; the previous pointer tells
		// us which IPs are new and need a GARP/UNA.
		old := l.desired.Swap(&desired)
		for ip := range desired.All() {
			if old == nil || !(*old).Contains(ip) {
				l.sendGARP(ip)
			}
		}
	}
}

// startListener opens a raw socket on the given interface and starts a
// listener goroutine.
func (m *proxyNeighManager) startListener(ifaceName string) error {
	l := &ifaceListener{
		ifaceName:   ifaceName,
		readTimeout: m.readTimeout,
		done:        make(chan struct{}),
	}

	l.ctx, l.cancel = context.WithCancel(m.ctx)

	if m.ipVersion == 4 {
		client, hwAddr, err := m.arpFactory(ifaceName)
		if err != nil {
			l.cancel()
			return err
		}
		l.arpCli = client
		l.hwAddr = hwAddr
		go l.runARPListener()
	} else {
		conn, hwAddr, err := m.ndpFactory(ifaceName)
		if err != nil {
			l.cancel()
			return err
		}
		l.ndpCli = conn
		l.hwAddr = hwAddr
		go l.runNDPListener()
	}

	m.listeners[ifaceName] = l
	logrus.WithField("iface", ifaceName).Info("Started proxy neighbor listener")
	return nil
}

// ifaceListener manages a raw socket listener for a single host interface.
type ifaceListener struct {
	ifaceName string
	// desired is the set of IPs this listener answers ARP/NDP for. Built fresh
	// and swapped atomically; never mutated after publishing.
	desired     atomic.Pointer[set.Set[string]]
	arpCli      arpClient // IPv4 only
	ndpCli      ndpConn   // IPv6 only
	hwAddr      net.HardwareAddr
	readTimeout time.Duration
	ctx         context.Context
	cancel      context.CancelFunc
	done        chan struct{}
	failed      atomic.Bool
}

// stop cancels the listener goroutine, closes its raw socket, and waits for the
// goroutine to exit.
func (l *ifaceListener) stop() {
	l.cancel()
	if l.arpCli != nil {
		err := l.arpCli.Close()
		if err != nil {
			logrus.WithError(err).WithField("iface", l.ifaceName).Warn("Failed to close ARP client")
		}
	}
	if l.ndpCli != nil {
		err := l.ndpCli.Close()
		if err != nil {
			logrus.WithError(err).WithField("iface", l.ifaceName).Warn("Failed to close NDP client")
		}
	}
	<-l.done
	logrus.WithField("iface", l.ifaceName).Info("Stopped proxy neighbor listener")
}

// runARPListener listens for ARP requests on a raw socket and replies for
// IPs in the desired set.
func (l *ifaceListener) runARPListener() {
	defer close(l.done)

	for {
		if l.ctx.Err() != nil {
			logrus.WithField("iface", l.ifaceName).Debug("ARP listener stopping: context cancelled")
			return
		}

		if err := l.arpCli.SetReadDeadline(time.Now().Add(l.readTimeout)); err != nil {
			logrus.WithError(err).WithField("iface", l.ifaceName).Warn("Failed to set ARP read deadline")
		}

		pkt, _, err := l.arpCli.Read()
		if err != nil {
			if l.ctx.Err() != nil {
				logrus.WithField("iface", l.ifaceName).Debug("ARP listener stopping: context cancelled during read")
				return
			}
			if err, ok := errors.AsType[net.Error](err); ok && err.Timeout() {
				continue
			}
			// Unrecoverable socket error: flag this listener so the manager
			// drops it and recreates a fresh one on the next reconcile.
			logrus.WithError(err).WithField("iface", l.ifaceName).Warn("ARP listener read failed; recreating listener")
			l.failed.Store(true)
			return
		}

		if pkt.Operation != arp.OperationRequest {
			continue
		}

		targetIP := pkt.TargetIP.String()
		desired := l.desired.Load()
		if desired == nil || !(*desired).Contains(targetIP) {
			continue
		}

		if err := l.arpCli.Reply(pkt, l.hwAddr, pkt.TargetIP); err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"iface": l.ifaceName,
				"ip":    targetIP,
			}).Warn("ARP listener: failed to send reply")
		}
	}
}

// runNDPListener listens for Neighbor Solicitations on a raw ICMPv6 socket
// and replies with Neighbor Advertisements for IPs in the desired set.
func (l *ifaceListener) runNDPListener() {
	defer close(l.done)

	for {
		if l.ctx.Err() != nil {
			logrus.WithField("iface", l.ifaceName).Debug("NDP listener stopping: context cancelled")
			return
		}

		if err := l.ndpCli.SetReadDeadline(time.Now().Add(l.readTimeout)); err != nil {
			logrus.WithError(err).WithField("iface", l.ifaceName).Warn("Failed to set NDP read deadline")
		}

		msg, _, srcAddr, err := l.ndpCli.ReadFrom()
		if err != nil {
			if l.ctx.Err() != nil {
				logrus.WithField("iface", l.ifaceName).Debug("NDP listener stopping: context cancelled during read")
				return
			}
			if netErr, ok := errors.AsType[net.Error](err); ok && netErr.Timeout() {
				continue
			}
			// Unrecoverable socket error: flag this listener so the manager
			// drops it and recreates a fresh one on the next reconcile.
			logrus.WithError(err).WithField("iface", l.ifaceName).Warn("NDP listener read failed; recreating listener")
			l.failed.Store(true)
			return
		}

		ns, ok := msg.(*ndp.NeighborSolicitation)
		if !ok {
			continue
		}

		targetIP := ns.TargetAddress.String()
		desired := l.desired.Load()
		if desired == nil || !(*desired).Contains(targetIP) {
			continue
		}

		// If the NS source is the unspecified address (::), this is a
		// Duplicate Address Detection probe (RFC 4862). We can't unicast
		// back to ::, so reply to the all-nodes multicast address and
		// clear the Solicited flag (RFC 4861 §4.4).
		dst := srcAddr
		solicited := true
		if !srcAddr.IsValid() || srcAddr.IsUnspecified() {
			dst = netip.MustParseAddr(ipv6AllNodesMulticast)
			solicited = false
		}

		na := &ndp.NeighborAdvertisement{
			Solicited:     solicited,
			Override:      true,
			TargetAddress: ns.TargetAddress,
			Options: []ndp.Option{
				&ndp.LinkLayerAddress{
					Direction: ndp.Target,
					Addr:      l.hwAddr,
				},
			},
		}
		if err := l.ndpCli.WriteTo(na, nil, dst); err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"iface": l.ifaceName,
				"ip":    targetIP,
			}).Debug("NDP listener: failed to send NA")
		}
	}
}

// sendGARP parses ipStr and dispatches to the IPv4 (gratuitous ARP) or IPv6
// (unsolicited NA) sender, based on which raw socket this listener holds.
func (l *ifaceListener) sendGARP(ipStr string) {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		logrus.WithError(err).WithField("ip", ipStr).Debug("Failed to parse IP for GARP")
		return
	}
	if l.arpCli != nil {
		l.sendGARPV4(addr)
	} else {
		l.sendGARPV6(addr)
	}
}

// sendGARPV4 sends a gratuitous ARP for ip using the listener's raw socket.
func (l *ifaceListener) sendGARPV4(ip netip.Addr) {
	pkt, err := arp.NewPacket(arp.OperationRequest, l.hwAddr, ip, ethernet.Broadcast, ip)
	if err != nil {
		logrus.WithError(err).WithField("ip", ip).Debug("Failed to create GARP packet")
		return
	}
	if err := l.arpCli.WriteTo(pkt, ethernet.Broadcast); err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"iface": l.ifaceName,
			"ip":    ip,
		}).Warn("Failed to send GARP")
	} else {
		logrus.WithFields(logrus.Fields{
			"iface": l.ifaceName,
			"ip":    ip,
		}).Debug("Sent gratuitous ARP")
	}
}

// sendGARPV6 sends an unsolicited Neighbor Advertisement for addr using the
// listener's raw socket.
func (l *ifaceListener) sendGARPV6(addr netip.Addr) {
	na := &ndp.NeighborAdvertisement{
		Override:      true,
		TargetAddress: addr,
		Options: []ndp.Option{
			&ndp.LinkLayerAddress{
				Direction: ndp.Target,
				Addr:      l.hwAddr,
			},
		},
	}
	if err := l.ndpCli.WriteTo(na, nil, netip.MustParseAddr(ipv6AllNodesMulticast)); err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"iface": l.ifaceName,
			"ip":    addr,
		}).Warn("Failed to send unsolicited NA")
	} else {
		logrus.WithFields(logrus.Fields{
			"iface": l.ifaceName,
			"ip":    addr,
		}).Debug("Sent unsolicited NA")
	}
}

// selectNodeForIP reports whether this node is the one the hash ring assigns to
// answer ARP/NDP for the given LoadBalancer IP. The ring assigns each IP to
// exactly one live node, spreading VIPs evenly across the cluster.
func (m *proxyNeighManager) selectNodeForIP(ipStr string) bool {
	owner, ok := m.nodeRing.Lookup(ipStr)
	selected := ok && owner == m.hostname
	if selected {
		logrus.WithField("ip", ipStr).Debug("This node owns the LoadBalancer IP")
	}
	return selected
}

func (m *proxyNeighManager) isMatchingIPVersion(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if m.ipVersion == 4 {
		return ip.To4() != nil
	}
	return ip.To4() == nil
}

func isNoEncapPool(pool *proto.IPAMPool) bool {
	return (v3.EncapMode(pool.IpipMode) == v3.Never || v3.IPIPMode(pool.IpipMode) == v3.IPIPModeNever) &&
		(v3.EncapMode(pool.VxlanMode) == v3.Never || v3.VXLANMode(pool.VxlanMode) == v3.VXLANModeNever)
}

func (m *proxyNeighManager) isInNoEncapPool(ip net.IP) bool {
	for _, cidr := range m.noEncapPools {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// refreshHostIface re-reads the addresses configured on ifaceName from netlink
// (to get real subnet CIDRs — the ifaceAddrsUpdate message only carries bare
// IPs) and updates m.hostIfaceToCIDRs. On any netlink failure the entry is
// dropped, matching removeHostIface behavior.
func (m *proxyNeighManager) refreshHostIface(ifaceName string) {
	link, err := m.nlHandle.LinkByName(ifaceName)
	if err != nil {
		logrus.WithError(err).WithField("iface", ifaceName).Debug("Failed to look up interface for CIDR update")
		delete(m.hostIfaceToCIDRs, ifaceName)
		return
	}

	family := netlink.FAMILY_V4
	if m.ipVersion == 6 {
		family = netlink.FAMILY_V6
	}

	addrs, err := m.nlHandle.AddrList(link, family)
	if err != nil {
		logrus.WithError(err).WithField("iface", ifaceName).Debug("Failed to list addresses for interface")
		delete(m.hostIfaceToCIDRs, ifaceName)
		return
	}

	var cidrs []net.IPNet
	for _, addr := range addrs {
		if addr.IPNet == nil {
			continue
		}
		cidrs = append(cidrs, *addr.IPNet)
	}

	logrus.WithFields(logrus.Fields{
		"iface": ifaceName,
		"cidrs": cidrs,
	}).Debug("Proxy neighbor manager refreshed host interface CIDRs from AddrList")

	if len(cidrs) > 0 {
		m.hostIfaceToCIDRs[ifaceName] = cidrs
	} else {
		delete(m.hostIfaceToCIDRs, ifaceName)
	}
}
