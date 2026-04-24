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
	"hash/fnv"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mdlayher/arp"
	"github.com/mdlayher/ethernet"
	"github.com/mdlayher/ndp"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/ipv6"

	"github.com/projectcalico/calico/felix/netlinkshim"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
)

// desiredIPSet is an immutable set of IPs that a listener goroutine reads to
// decide whether to respond to an ARP/NDP request. Swapped atomically.
type desiredIPSet map[string]bool

// serviceID identifies a Kubernetes Service by namespace and name. Used as a
// map key for tracking LoadBalancer service IPs.
type serviceID struct {
	Namespace string
	Name      string
}

// arpClient abstracts the mdlayher/arp.Client for testing.
type arpClient interface {
	Read() (*arp.Packet, *ethernet.Frame, error)
	Reply(req *arp.Packet, hwAddr net.HardwareAddr, ip netip.Addr) error
	WriteTo(p *arp.Packet, addr net.HardwareAddr) error
	SetReadDeadline(t time.Time) error
	Close() error
}

// ndpConn abstracts the mdlayher/ndp.Conn for testing.
type ndpConn interface {
	ReadFrom() (ndp.Message, *ipv6.ControlMessage, netip.Addr, error)
	WriteTo(m ndp.Message, cm *ipv6.ControlMessage, dst netip.Addr) error
	SetReadDeadline(t time.Time) error
	Close() error
}

type arpClientFactory func(ifaceName string) (arpClient, net.HardwareAddr, error)
type ndpConnFactory func(ifaceName string) (ndpConn, net.HardwareAddr, error)

// ifaceListener manages a raw socket listener for a single host interface.
type ifaceListener struct {
	ifaceName string
	desired   atomic.Pointer[desiredIPSet]
	arpCli    arpClient // IPv4 only
	ndpCli    ndpConn   // IPv6 only
	hwAddr    net.HardwareAddr
	cancel    context.CancelFunc
	done      chan struct{}
}

// proxyNeighManager automatically responds to ARP (IPv4) and NDP (IPv6) requests for
// pod and LoadBalancer IPs that fall within the same L2 subnet as a host interface.
// Instead of programming kernel proxy neighbor entries, it listens on raw sockets and
// responds directly in userspace.
type proxyNeighManager struct {
	ipVersion      uint8
	hostname       string
	wlIfacesRegexp *regexp.Regexp

	// hostIfaceToCIDRs maps host interface name to the parsed CIDRs on that interface.
	hostIfaceToCIDRs map[string][]net.IPNet

	// localWorkloadIPs maps workload endpoint ID to the pod's IP strings.
	localWorkloadIPs map[types.WorkloadEndpointID][]string

	// lbServiceIPs maps service ID to LoadBalancer ingress IP strings.
	lbServiceIPs map[serviceID][]string

	// clusterNodes is the set of hostnames known to the cluster. Used as the
	// hash ring for LB VIP node selection.
	clusterNodes map[string]struct{}

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
		log.WithError(err).Panic("Failed to create netlink handle for proxy neighbor manager")
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
			return conn, ifi.HardwareAddr, nil
		}
	}
	return newProxyNeighManagerWithShims(dpConfig, ipVersion, nl, af, nf)
}

func newProxyNeighManagerWithShims(
	dpConfig Config,
	ipVersion uint8,
	nl netlinkshim.Interface,
	af arpClientFactory,
	nf ndpConnFactory,
) *proxyNeighManager {
	wlIfacesPattern := "^(" + strings.Join(dpConfig.RulesConfig.WorkloadIfacePrefixes, "|") + ").*"
	wlIfacesRegexp := regexp.MustCompile(wlIfacesPattern)

	ctx, cancel := context.WithCancel(context.Background())
	return &proxyNeighManager{
		ipVersion:        ipVersion,
		hostname:         dpConfig.Hostname,
		wlIfacesRegexp:   wlIfacesRegexp,
		hostIfaceToCIDRs: make(map[string][]net.IPNet),
		localWorkloadIPs: make(map[types.WorkloadEndpointID][]string),
		lbServiceIPs:     make(map[serviceID][]string),
		clusterNodes:     make(map[string]struct{}),
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
			return
		}
		log.WithFields(log.Fields{
			"ifaceName": msg.Name,
			"addrs":     msg.Addrs,
		}).Debug("Proxy neighbor manager received ifaceAddrsUpdate")
		if msg.Addrs == nil {
			m.removeHostIface(msg.Name)
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
		log.WithFields(log.Fields{
			"workload":      wlKey,
			"ips":           ips,
			"migrationRole": ep.LiveMigrationRole,
		}).Debug("Proxy neighbor manager received WorkloadEndpointUpdate")
		if ep.LiveMigrationRole == proto.LiveMigrationRole_SOURCE {
			delete(m.localWorkloadIPs, wlKey)
		} else if len(ips) > 0 {
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
			log.WithField("workload", wlKey).Debug("Proxy neighbor manager received WorkloadEndpointRemove")
			delete(m.localWorkloadIPs, wlKey)
			m.dirty = true
		}

	case *proto.ServiceUpdate:
		svcKey := serviceID{Namespace: msg.Namespace, Name: msg.Name}
		if msg.Type != "LoadBalancer" {
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
		log.WithFields(log.Fields{
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
			log.WithField("service", svcKey).Debug("Proxy neighbor manager received ServiceRemove")
			delete(m.lbServiceIPs, svcKey)
			m.dirty = true
		}

	case *proto.HostMetadataV4V6Update:
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
		log.WithField("hostname", msg.Hostname).Debug("Proxy neighbor manager received HostMetadataV4V6Update")
		m.clusterNodes[msg.Hostname] = struct{}{}
		m.dirty = true

	case *proto.HostMetadataV4V6Remove:
		if _, ok := m.clusterNodes[msg.Hostname]; ok {
			log.WithField("hostname", msg.Hostname).Debug("Proxy neighbor manager received HostMetadataV4V6Remove")
			delete(m.clusterNodes, msg.Hostname)
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
				log.WithError(err).WithField("cidr", pool.Cidr).Warn("Failed to parse IPPool CIDR")
				return
			}
			log.WithFields(log.Fields{
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
			log.WithField("poolID", msg.Id).Debug("Proxy neighbor manager received IPAMPoolRemove")
			delete(m.noEncapPools, msg.Id)
			m.dirty = true
		}
	}
}

func (m *proxyNeighManager) CompleteDeferredWork() error {
	if !m.dirty {
		return nil
	}
	m.dirty = false

	log.WithFields(log.Fields{
		"numWorkloads":  len(m.localWorkloadIPs),
		"numHostIfaces": len(m.hostIfaceToCIDRs),
		"numLBServices": len(m.lbServiceIPs),
		"numNodes":      len(m.clusterNodes),
	}).Debug("Proxy neighbor manager CompleteDeferredWork")

	// Build desired state: which IPs should each interface respond to.
	desiredByIface := make(map[string]desiredIPSet)

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

	// Reconcile listeners: start new ones, stop removed ones.
	var startErr error
	for ifaceName := range desiredByIface {
		if _, ok := m.listeners[ifaceName]; !ok {
			if err := m.startListener(ifaceName); err != nil {
				log.WithError(err).WithField("iface", ifaceName).Warn("Failed to start listener; will retry")
				// Re-mark dirty so the next CompleteDeferredWork retries,
				// and remember the error to surface it to the dataplane loop.
				m.dirty = true
				startErr = err
			}
		}
	}
	for ifaceName, l := range m.listeners {
		if _, ok := desiredByIface[ifaceName]; !ok {
			m.stopListener(l)
			delete(m.listeners, ifaceName)
		}
	}

	// Swap desired IP sets and send GARP/UNA for newly-appearing IPs.
	for ifaceName, desired := range desiredByIface {
		l, ok := m.listeners[ifaceName]
		if !ok {
			continue
		}
		// Atomically swap in the new desired set; the previous pointer tells
		// us which IPs are new and need a GARP/UNA.
		d := desired
		old := l.desired.Swap(&d)
		for ip := range desired {
			if old == nil || !(*old)[ip] {
				m.sendGARP(l, ip)
			}
		}
	}

	return startErr
}

// addMatchingIPs adds the IP to the desired set for every host interface whose subnet
// contains it.
func (m *proxyNeighManager) addMatchingIPs(desiredByIface map[string]desiredIPSet, ip net.IP) {
	for ifaceName, cidrs := range m.hostIfaceToCIDRs {
		for _, cidr := range cidrs {
			if cidr.Contains(ip) {
				if desiredByIface[ifaceName] == nil {
					desiredByIface[ifaceName] = make(desiredIPSet)
				}
				desiredByIface[ifaceName][ip.String()] = true
				break
			}
		}
	}
}

// startListener opens a raw socket on the given interface and starts a
// listener goroutine.
func (m *proxyNeighManager) startListener(ifaceName string) error {
	l := &ifaceListener{
		ifaceName: ifaceName,
		done:      make(chan struct{}),
	}

	ctx, cancel := context.WithCancel(m.ctx)
	l.cancel = cancel

	if m.ipVersion == 4 {
		client, hwAddr, err := m.arpFactory(ifaceName)
		if err != nil {
			cancel()
			return err
		}
		l.arpCli = client
		l.hwAddr = hwAddr
		go m.runARPListener(ctx, l)
	} else {
		conn, hwAddr, err := m.ndpFactory(ifaceName)
		if err != nil {
			cancel()
			return err
		}
		l.ndpCli = conn
		l.hwAddr = hwAddr
		go m.runNDPListener(ctx, l)
	}

	m.listeners[ifaceName] = l
	log.WithField("iface", ifaceName).Info("Started proxy neighbor listener")
	return nil
}

// stopListener cancels and cleans up a listener.
func (m *proxyNeighManager) stopListener(l *ifaceListener) {
	l.cancel()
	if l.arpCli != nil {
		_ = l.arpCli.Close()
	}
	if l.ndpCli != nil {
		_ = l.ndpCli.Close()
	}
	<-l.done
	log.WithField("iface", l.ifaceName).Info("Stopped proxy neighbor listener")
}

// runARPListener listens for ARP requests on a raw socket and replies for
// IPs in the desired set.
func (m *proxyNeighManager) runARPListener(ctx context.Context, l *ifaceListener) {
	defer close(l.done)

	for {
		_ = l.arpCli.SetReadDeadline(time.Now().Add(1 * time.Second))

		pkt, _, err := l.arpCli.Read()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// Timeout or transient error — keep looping.
			continue
		}

		if pkt.Operation != arp.OperationRequest {
			continue
		}

		targetIP := pkt.TargetIP.String()
		desired := l.desired.Load()
		if desired == nil || !(*desired)[targetIP] {
			continue
		}

		if err := l.arpCli.Reply(pkt, l.hwAddr, pkt.TargetIP); err != nil {
			log.WithError(err).WithFields(log.Fields{
				"iface": l.ifaceName,
				"ip":    targetIP,
			}).Debug("ARP listener: failed to send reply")
		}
	}
}

// runNDPListener listens for Neighbor Solicitations on a raw ICMPv6 socket
// and replies with Neighbor Advertisements for IPs in the desired set.
func (m *proxyNeighManager) runNDPListener(ctx context.Context, l *ifaceListener) {
	defer close(l.done)

	for {
		_ = l.ndpCli.SetReadDeadline(time.Now().Add(1 * time.Second))

		msg, _, srcAddr, err := l.ndpCli.ReadFrom()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}

		ns, ok := msg.(*ndp.NeighborSolicitation)
		if !ok {
			continue
		}

		targetIP := ns.TargetAddress.String()
		desired := l.desired.Load()
		if desired == nil || !(*desired)[targetIP] {
			continue
		}

		// If the NS source is the unspecified address (::), this is a
		// Duplicate Address Detection probe (RFC 4862). We can't unicast
		// back to ::, so reply to the all-nodes multicast address and
		// clear the Solicited flag (RFC 4861 §4.4).
		dst := srcAddr
		solicited := true
		if !srcAddr.IsValid() || srcAddr.IsUnspecified() {
			dst = netip.MustParseAddr("ff02::1")
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
			log.WithError(err).WithFields(log.Fields{
				"iface": l.ifaceName,
				"ip":    targetIP,
			}).Debug("NDP listener: failed to send NA")
		}
	}
}

// sendGARP sends a gratuitous ARP (IPv4) or unsolicited NA (IPv6) for the
// given IP using the listener's raw socket.
func (m *proxyNeighManager) sendGARP(l *ifaceListener, ipStr string) {
	if m.ipVersion == 4 {
		ip, err := netip.ParseAddr(ipStr)
		if err != nil {
			return
		}
		pkt, err := arp.NewPacket(arp.OperationRequest, l.hwAddr, ip, ethernet.Broadcast, ip)
		if err != nil {
			log.WithError(err).WithField("ip", ipStr).Debug("Failed to create GARP packet")
			return
		}
		if err := l.arpCli.WriteTo(pkt, ethernet.Broadcast); err != nil {
			log.WithError(err).WithFields(log.Fields{
				"iface": l.ifaceName,
				"ip":    ipStr,
			}).Warn("Failed to send GARP")
		} else {
			log.WithFields(log.Fields{
				"iface": l.ifaceName,
				"ip":    ipStr,
			}).Debug("Sent gratuitous ARP")
		}
	} else {
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			return
		}
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
		allNodes := netip.MustParseAddr("ff02::1")
		if err := l.ndpCli.WriteTo(na, nil, allNodes); err != nil {
			log.WithError(err).WithFields(log.Fields{
				"iface": l.ifaceName,
				"ip":    ipStr,
			}).Warn("Failed to send unsolicited NA")
		} else {
			log.WithFields(log.Fields{
				"iface": l.ifaceName,
				"ip":    ipStr,
			}).Debug("Sent unsolicited NA")
		}
	}
}

// selectNodeForIP uses Rendezvous hashing (Highest Random Weight) to select
// which cluster node should answer ARP for the given IP.
func (m *proxyNeighManager) selectNodeForIP(ipStr string) bool {
	if len(m.clusterNodes) == 0 {
		return false
	}
	var bestScore uint32
	var bestNode string
	for hostname := range m.clusterNodes {
		h := fnv.New32a()
		_, _ = h.Write([]byte(ipStr))
		_, _ = h.Write([]byte(hostname))
		score := h.Sum32()
		if score > bestScore || (score == bestScore && hostname > bestNode) {
			bestScore = score
			bestNode = hostname
		}
	}
	return bestNode == m.hostname
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
	return (pool.IpipMode == "" || strings.EqualFold(pool.IpipMode, "Never")) &&
		(pool.VxlanMode == "" || strings.EqualFold(pool.VxlanMode, "Never"))
}

func (m *proxyNeighManager) isInNoEncapPool(ip net.IP) bool {
	for _, cidr := range m.noEncapPools {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// removeHostIface drops any tracked subnet info for ifaceName. Used when the
// interface goes away.
func (m *proxyNeighManager) removeHostIface(ifaceName string) {
	delete(m.hostIfaceToCIDRs, ifaceName)
}

// refreshHostIface re-reads the addresses configured on ifaceName from netlink
// (to get real subnet CIDRs — the ifaceAddrsUpdate message only carries bare
// IPs) and updates m.hostIfaceToCIDRs. On any netlink failure the entry is
// dropped, matching removeHostIface behavior.
func (m *proxyNeighManager) refreshHostIface(ifaceName string) {
	link, err := m.nlHandle.LinkByName(ifaceName)
	if err != nil {
		log.WithError(err).WithField("iface", ifaceName).Debug("Failed to look up interface for CIDR update")
		delete(m.hostIfaceToCIDRs, ifaceName)
		return
	}

	family := netlink.FAMILY_V4
	if m.ipVersion == 6 {
		family = netlink.FAMILY_V6
	}

	addrs, err := m.nlHandle.AddrList(link, family)
	if err != nil {
		log.WithError(err).WithField("iface", ifaceName).Debug("Failed to list addresses for interface")
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

	log.WithFields(log.Fields{
		"iface": ifaceName,
		"cidrs": cidrs,
	}).Debug("Proxy neighbor manager refreshed host interface CIDRs from AddrList")

	if len(cidrs) > 0 {
		m.hostIfaceToCIDRs[ifaceName] = cidrs
	} else {
		delete(m.hostIfaceToCIDRs, ifaceName)
	}
}
