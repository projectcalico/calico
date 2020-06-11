// Copyright (c) 2017-2020 Tigera, Inc. All rights reserved.
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

package proxy

import (
	"context"
	"fmt"

	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	k8sp "k8s.io/kubernetes/pkg/proxy"

	"github.com/projectcalico/felix/bpf"
	"github.com/projectcalico/felix/bpf/conntrack"
	"github.com/projectcalico/felix/bpf/nat"
	"github.com/projectcalico/felix/bpf/routes"
	"github.com/projectcalico/felix/ip"
)

var podNPIP = net.IPv4(255, 255, 255, 255)

type svcInfo struct {
	id         uint32
	count      int
	localCount int
	svc        k8sp.ServicePort
}

type svcKey struct {
	sname k8sp.ServicePortName
	extra string
}

func (k svcKey) String() string {
	if k.extra == "" {
		return k.sname.String()
	}

	return fmt.Sprintf("%s:%s", k.extra, k.sname)
}

func getSvcKey(sname k8sp.ServicePortName, extra string) svcKey {
	return svcKey{
		sname: sname,
		extra: extra,
	}
}

type svcType int

const (
	svcTypeExternalIP svcType = iota
	svcTypeNodePort
	svcTypeNodePortRemote
)

var svcType2String = map[svcType]string{
	svcTypeNodePort:       "NodePort",
	svcTypeExternalIP:     "ExternalIP",
	svcTypeNodePortRemote: "NodePortRemote",
}

func getSvcKeyExtra(t svcType, ip string) string {
	return svcType2String[t] + ":" + ip
}

func hasSvcKeyExtra(skey svcKey, t svcType) bool {
	return strings.HasPrefix(skey.extra, svcType2String[t]+":")
}

func isSvcKeyDerived(skey svcKey) bool {
	return hasSvcKeyExtra(skey, svcTypeExternalIP) || hasSvcKeyExtra(skey, svcTypeNodePort)
}

type stickyFrontend struct {
	id    uint32
	timeo time.Duration
}

// Syncer is an implementation of DPSyncer interface. It is not thread safe and
// should be called only once at a time
type Syncer struct {
	bpfSvcs bpf.Map
	bpfEps  bpf.Map
	bpfAff  bpf.Map

	nextSvcID uint32

	nodePortIPs []net.IP
	rt          Routes

	// new maps are valid during the Apply()'s runtime to provide easy access
	// to updating them. They become prev at the end of it to be compared
	// against in the next iteration
	newSvcMap  map[svcKey]svcInfo
	newEpsMap  k8sp.EndpointsMap
	prevSvcMap map[svcKey]svcInfo
	prevEpsMap k8sp.EndpointsMap
	// active Maps contain all active svcs endpoints at the end of an iteration
	activeSvcsMap map[ipPortProto]uint32
	activeEpsMap  map[uint32]map[ipPort]struct{}

	// We never have more than one thread accessing the [prev|new][Svc|Eps]Map,
	// this is to just make sure and to make the --race checker happy
	mapsLck sync.Mutex

	// synced is true after reconciling the first Apply
	synced bool
	// origs are deallocated after the first Apply reconciles
	origSvcs nat.MapMem
	origEps  nat.BackendMapMem

	expFixupWg   sync.WaitGroup
	expFixupStop chan struct{}

	stop     chan struct{}
	stopOnce sync.Once

	stickySvcs       map[nat.FrontEndAffinityKey]stickyFrontend
	stickyEps        map[uint32]map[nat.BackendValue]struct{}
	stickySvcDeleted bool

	conntrackScanner *conntrack.Scanner
}

type ipPort struct {
	ip   string
	port int
}

type ipPortProto struct {
	ipPort
	proto uint8
}

func servicePortToIPPortProto(sp k8sp.ServicePort) ipPortProto {
	return ipPortProto{
		ipPort: ipPort{
			ip:   sp.ClusterIP().String(),
			port: sp.Port(),
		},
		proto: ProtoV1ToIntPanic(sp.Protocol()),
	}
}

func uniqueIPs(ips []net.IP) []net.IP {
	m := make(map[string]net.IP)
	unique := true

	for _, ip := range ips {
		s := ip.String()
		if _, ok := m[s]; ok {
			unique = false
		} else {
			m[s] = ip
		}
	}

	if unique {
		return ips
	}

	ret := make([]net.IP, 0, len(m))
	for _, ip := range m {
		ret = append(ret, ip)
	}

	return ret
}

// NewSyncer returns a new Syncer
func NewSyncer(nodePortIPs []net.IP, svcsmap, epsmap, affmap, ctmap bpf.Map, rt Routes) (*Syncer, error) {
	s := &Syncer{
		bpfSvcs:     svcsmap,
		bpfEps:      epsmap,
		bpfAff:      affmap,
		rt:          rt,
		nodePortIPs: uniqueIPs(nodePortIPs),
		prevSvcMap:  make(map[svcKey]svcInfo),
		prevEpsMap:  make(k8sp.EndpointsMap),
		stop:        make(chan struct{}),
	}

	s.conntrackScanner = conntrack.NewScanner(ctmap, conntrack.NewStaleNATScanner(s.frontendHasBackend))

	if err := s.loadOrigs(); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *Syncer) loadOrigs() error {

	svcs, err := nat.LoadFrontendMap(s.bpfSvcs)
	if err != nil {
		return err
	}

	eps, err := nat.LoadBackendMap(s.bpfEps)
	if err != nil {
		return err
	}

	s.origSvcs = svcs
	s.origEps = eps

	return nil
}

func (s *Syncer) startupSync(state DPSyncerState) error {
	for svck, svcv := range s.origSvcs {
		svckey := s.matchBpfSvc(svck, state.SvcMap)
		if svckey == nil {
			continue
		}

		id := svcv.ID()
		count := int(svcv.Count())
		s.prevSvcMap[*svckey] = svcInfo{
			id:         id,
			count:      count,
			localCount: int(svcv.LocalCount()),
			svc:        state.SvcMap[svckey.sname],
		}

		delete(s.origSvcs, svck)

		if id >= s.nextSvcID {
			s.nextSvcID = id + 1
		}

		if svckey.extra != "" {
			continue
		}

		for i := 0; i < count; i++ {
			epk := nat.NewNATBackendKey(id, uint32(i))
			ep, ok := s.origEps[epk]
			if !ok {
				log.Debugf("s.origSvcs = %+v\n", s.origSvcs)
				log.Debugf("s.origEps = %+v\n", s.origEps)
				return errors.Errorf("inconsistent backed map, missing ep %s", epk)
			}
			s.prevEpsMap[svckey.sname] = append(s.prevEpsMap[svckey.sname],
				&k8sp.BaseEndpointInfo{
					Endpoint: net.JoinHostPort(ep.Addr().String(), strconv.Itoa(int(ep.Port()))),
					// IsLocal is not importatnt here
				})
			delete(s.origEps, epk)
		}
	}

	for k := range s.origSvcs {
		log.Debugf("removing stale %s", k)
		if err := s.bpfSvcs.Delete(k[:]); err != nil {
			return errors.Errorf("bpfSvcs.Delete: %s", err)
		}
	}

	for k := range s.origEps {
		log.Debugf("removing stale %s", k)
		if err := s.bpfEps.Delete(k[:]); err != nil {
			return errors.Errorf("bpfEps.Delete: %s", err)
		}
	}

	return nil
}

func (s *Syncer) cleanupDerived(id uint32) error {
	// also delete all derived
	for _, si := range s.prevSvcMap {
		if si.id == id {
			key, err := getSvcNATKey(si.svc)
			if err != nil {
				return err
			}

			log.Debugf("bpf map deleting derived %s:%s", key, nat.NewNATValue(id, 0, 0, 0))
			if err := s.bpfSvcs.Delete(key[:]); err != nil {
				return errors.Errorf("bpfSvcs.Delete: %s", err)
			}
			keys, err := getSvcNATKeyLBSrcRange(si.svc)
			if err != nil {
				return err
			}
			for _, key = range keys {
				log.Debugf("bpf map deleting derived %s:%s", key, nat.NewNATValue(id, 0, 0, 0))
				if err := s.bpfSvcs.Delete(key[:]); err != nil {
					return errors.Errorf("bpfSvcs.Delete: %s", err)
				}
			}
		}
	}

	return nil
}

func (s *Syncer) applySvc(skey svcKey, sinfo k8sp.ServicePort, eps []k8sp.Endpoint,
	cleanupDerived func(uint32) error) error {

	var (
		err   error
		id    uint32
		count int
		local int
	)

	old, exists := s.prevSvcMap[skey]
	if exists {
		if ServicePortEqual(old.svc, sinfo) {
			id = old.id
			count, local, err = s.updateExistingSvc(skey.sname, sinfo, id, old.count, eps)
		} else {
			if err := s.deleteSvc(old.svc, old.id, old.count); err != nil {
				return err
			}

			delete(s.prevSvcMap, skey)
			if cleanupDerived != nil {
				if err := cleanupDerived(old.id); err != nil {
					return errors.WithMessage(err, "cleanupDerived")
				}
			}

			exists = false
		}
	}
	if !exists {
		id = s.newSvcID()
		count, local, err = s.newSvc(skey.sname, sinfo, id, eps)
	}
	if err != nil {
		return err
	}

	s.newSvcMap[skey] = svcInfo{
		id:         id,
		count:      count,
		localCount: local,
		svc:        sinfo,
	}

	s.newEpsMap[skey.sname] = eps

	log.Debugf("applied a service %s update: sinfo=%+v", skey, s.newSvcMap[skey])

	return nil
}

func (s *Syncer) addActiveEps(id uint32, svc k8sp.ServicePort, eps []k8sp.Endpoint) {
	svcKey := servicePortToIPPortProto(svc)

	s.activeSvcsMap[svcKey] = id

	if len(eps) == 0 {
		return
	}

	epsmap := make(map[ipPort]struct{})
	s.activeEpsMap[id] = epsmap
	for _, ep := range eps {
		port, _ := ep.Port() // it is error free by this point
		epsmap[ipPort{
			ip:   ep.IP(),
			port: port,
		}] = struct{}{}
	}
}

func (s *Syncer) applyExpandedNP(sname k8sp.ServicePortName, sinfo k8sp.ServicePort,
	eps []k8sp.Endpoint, node ip.V4Addr, nport int) error {
	skey := getSvcKey(sname, getSvcKeyExtra(svcTypeNodePortRemote, node.String()))
	si := serviceInfoFromK8sServicePort(sinfo)
	si.clusterIP = node.AsNetIP()
	si.port = nport

	if err := s.applySvc(skey, si, eps, nil); err != nil {
		return errors.Errorf("apply NodePortRemote for %s node %s", sname, node)
	}

	return nil
}

type expandMiss struct {
	sname k8sp.ServicePortName
	sinfo k8sp.ServicePort
	eps   []k8sp.Endpoint
	nport int
}

func (s *Syncer) expandNodePorts(sname k8sp.ServicePortName, sinfo k8sp.ServicePort,
	eps []k8sp.Endpoint, nport int, rtLookup func(addr ip.Addr) (routes.Value, bool)) *expandMiss {

	m := make(map[ip.V4Addr][]k8sp.Endpoint)

	var miss *expandMiss

	for _, ep := range eps {
		ipv4 := ip.FromString(ep.IP()).(ip.V4Addr)

		rt, ok := rtLookup(ipv4)
		if !ok {
			log.Errorf("No route for %s", ipv4)
			if miss == nil {
				miss = &expandMiss{
					sname: sname,
					sinfo: sinfo,
					nport: nport,
				}
			}
			miss.eps = append(miss.eps, ep)
			continue
		}

		nodeIP := rt.NextHop().(ip.V4Addr)
		log.Debugf("found rt %s for dest %s", nodeIP, ipv4)

		m[nodeIP] = append(m[nodeIP], ep)
	}

	for node, neps := range m {
		if err := s.applyExpandedNP(sname, sinfo, neps, node, nport); err != nil {
			log.WithField("error", err).Errorf("Failed to expand NodePort")
		}
	}

	return miss
}

func (s *Syncer) applyDerived(sname k8sp.ServicePortName, t svcType, sinfo k8sp.ServicePort) error {

	svc, ok := s.newSvcMap[getSvcKey(sname, "")]
	if !ok {
		// this should not happen
		return errors.Errorf("no ClusterIP for derived service type %d", t)
	}

	var skey svcKey
	count := svc.count
	local := svc.localCount

	skey = getSvcKey(sname, getSvcKeyExtra(t, sinfo.ClusterIP().String()))
	switch t {
	case svcTypeNodePort:
		if sinfo.OnlyNodeLocalEndpoints() {
			count = local // use only local eps
		}
	}

	newInfo := svcInfo{
		id:         svc.id,
		count:      count,
		localCount: local,
		svc:        sinfo,
	}

	if oldInfo, ok := s.prevSvcMap[skey]; !ok || oldInfo != newInfo {
		if err := s.writeSvc(sinfo, svc.id, count, local); err != nil {
			return err
		}
		if svcTypeExternalIP == t {
			err := s.writeLBSrcRangeSvcNATKeys(sinfo, svc.id, count, local)
			if err != nil {
				log.Debugf("Failed to write LB source range NAT keys")
			}
		}
	}

	s.newSvcMap[skey] = newInfo
	log.Debugf("applied a derived service %s update: sinfo=%+v", skey, s.newSvcMap[skey])

	return nil
}

func (s *Syncer) apply(state DPSyncerState) error {
	log.Debugf("applying new state")

	// we need to copy the maps from the new state to compute the diff in the
	// next call. We cannot keep the provided maps as the generic k8s proxy code
	// updates them. This function is called with a lock help so we are safe
	// here and now.
	s.newSvcMap = make(map[svcKey]svcInfo)
	s.newEpsMap = make(k8sp.EndpointsMap)

	s.activeSvcsMap = make(map[ipPortProto]uint32)
	s.activeEpsMap = make(map[uint32]map[ipPort]struct{})

	defer func() {
		// free the maps when the iteration is complete
		s.activeSvcsMap = nil
		s.activeEpsMap = nil
	}()

	var expNPMisses []*expandMiss

	// insert or update existing services
	for sname, sinfo := range state.SvcMap {
		skey := getSvcKey(sname, "")
		eps := state.EpsMap[sname]
		if err := s.applySvc(skey, sinfo, eps, s.cleanupDerived); err != nil {
			return err
		}

		// N.B. we assume that k8s provide us with no duplicities
		for _, extIP := range sinfo.ExternalIPStrings() {
			extInfo := serviceInfoFromK8sServicePort(sinfo)
			extInfo.clusterIP = net.ParseIP(extIP)
			err := s.applyDerived(sname, svcTypeExternalIP, extInfo)
			if err != nil {
				log.Errorf("failed to apply ExternalIP %s for service %s : %s", extIP, sname, err)
				continue
			}
		}

		if nport := sinfo.NodePort(); nport != 0 {
			for _, npip := range s.nodePortIPs {
				npInfo := serviceInfoFromK8sServicePort(sinfo)
				npInfo.clusterIP = npip
				npInfo.port = nport
				if npip.Equal(podNPIP) && sinfo.OnlyNodeLocalEndpoints() {
					// do not program the meta entry, program each node
					// separately
					continue
				}
				err := s.applyDerived(sname, svcTypeNodePort, npInfo)
				if err != nil {
					log.Errorf("failed to apply NodePort %s for service %s : %s", npip, sname, err)
					continue
				}
			}
			if sinfo.OnlyNodeLocalEndpoints() {
				if miss := s.expandNodePorts(sname, sinfo, eps, nport, s.rt.Lookup); miss != nil {
					expNPMisses = append(expNPMisses, miss)
				}
			}
		}
	}

	// delete services that do not exist anymore now that we added new nodeports
	// and external ips
	for skey, sinfo := range s.prevSvcMap {
		if _, ok := s.newSvcMap[skey]; ok {
			continue
		}

		count := sinfo.count
		if isSvcKeyDerived(skey) {
			// do not delete backends if only deleting a service derived from a
			// ClusterIP, that is ExternalIP or NodePort
			count = 0
			log.Debugf("deleting derived svc %s", skey)
		}

		if err := s.deleteSvc(sinfo.svc, sinfo.id, count); err != nil {
			return err
		}

		if sinfo.svc.SessionAffinityType() == v1.ServiceAffinityClientIP {
			s.stickySvcDeleted = true
		}

		log.Infof("removed stale service %q", skey)
	}

	// build active maps for conntrack cleaning
	for skey, sinfo := range s.newSvcMap {
		if sinfo.count == 0 {
			continue
		}

		if isSvcKeyDerived(skey) {
			s.addActiveEps(sinfo.id, sinfo.svc, nil)
		} else {
			s.addActiveEps(sinfo.id, sinfo.svc, s.newEpsMap[skey.sname])
		}
	}

	log.Debugf("new state written")

	s.runExpandNPFixup(expNPMisses)
	s.conntrackScanner.Scan()

	return nil
}

// Apply applies the new state
func (s *Syncer) Apply(state DPSyncerState) error {
	if !s.synced {
		log.Infof("Syncing k8s state and bpf maps after start")
		if err := s.startupSync(state); err != nil {
			return errors.WithMessage(err, "startup sync")
		}
		s.synced = true
		// deallocate, no further use
		s.origSvcs = nil
		s.origEps = nil
		log.Infof("Startup sync complete")
	} else {
		// if we were not synced yet, the fixer cannot run yet
		s.stopExpandNPFixup()

		s.prevSvcMap = s.newSvcMap
		s.prevEpsMap = s.newEpsMap
	}

	// preallocate maps the track sticky service for cleanup
	s.stickySvcs = make(map[nat.FrontEndAffinityKey]stickyFrontend)
	s.stickyEps = make(map[uint32]map[nat.BackendValue]struct{})
	s.stickySvcDeleted = false

	defer func() {
		// not needed anymore
		s.stickySvcs = nil
		s.stickyEps = nil
	}()

	s.mapsLck.Lock()
	defer s.mapsLck.Unlock()

	if err := s.apply(state); err != nil {
		// dont bother to cleanup affinity since we do not know in what state we
		// are anyway. Will get resolved once we get in a good state
		return err
	}

	// We wrote all updates, noone will create new records in affinity table
	// that we would clean up now, so do it!
	return s.cleanupSticky()
}

func (s *Syncer) updateExistingSvc(sname k8sp.ServicePortName, sinfo k8sp.ServicePort, id uint32,
	oldCount int, eps []k8sp.Endpoint) (int, int, error) {

	// No need to delete any old entries if we do reduce the number of backends
	// as all the key:value are going to be rewritten/updated
	if oldCount > len(eps) {
		for i := 0; i < oldCount; i++ {
			if err := s.deleteSvcBackend(id, uint32(i)); err != nil {
				return 0, 0, err
			}
		}
	}

	return s.newSvc(sname, sinfo, id, eps)
}

func (s *Syncer) newSvc(sname k8sp.ServicePortName, sinfo k8sp.ServicePort, id uint32,
	eps []k8sp.Endpoint) (int, int, error) {

	cpEps := make([]k8sp.Endpoint, 0, len(eps))

	cnt := 0
	local := 0

	if sinfo.SessionAffinityType() == v1.ServiceAffinityClientIP {
		// since we write the backend before we write the frontend, we need to
		// preallocate the map for it
		s.stickyEps[id] = make(map[nat.BackendValue]struct{})
	}

	for _, ep := range eps {
		if !ep.GetIsLocal() {
			continue
		}
		if err := s.writeSvcBackend(id, uint32(cnt), ep); err != nil {
			return 0, 0, err
		}

		cpEps = append(cpEps, ep)
		cnt++
		local++
	}

	for _, ep := range eps {
		if ep.GetIsLocal() {
			continue
		}
		if err := s.writeSvcBackend(id, uint32(cnt), ep); err != nil {
			return 0, 0, err
		}

		cpEps = append(cpEps, ep)
		cnt++
	}

	if err := s.writeSvc(sinfo, id, cnt, local); err != nil {
		return 0, 0, err
	}

	s.newEpsMap[sname] = cpEps

	return cnt, local, nil
}

func (s *Syncer) writeSvcBackend(svcID uint32, idx uint32, ep k8sp.Endpoint) error {
	ip := net.ParseIP(ep.IP())

	key := nat.NewNATBackendKey(svcID, uint32(idx))

	tgtPort, err := ep.Port()
	if err != nil {
		return errors.Errorf("no port for endpoint %q: %s", ep, err)
	}
	val := nat.NewNATBackendValue(ip, uint16(tgtPort))

	log.Debugf("bpf map writing %s:%s", key, val)
	if err := s.bpfEps.Update(key[:], val[:]); err != nil {
		return errors.Errorf("bpfEps.Update: %s", err)
	}

	if s.stickyEps[svcID] != nil {
		s.stickyEps[svcID][val] = struct{}{}
	}

	return nil
}

func (s *Syncer) deleteSvcBackend(svcID uint32, idx uint32) error {
	key := nat.NewNATBackendKey(svcID, uint32(idx))
	log.Debugf("bpf map deleting %s", key)
	if err := s.bpfEps.Delete(key[:]); err != nil {
		return errors.Errorf("bpfEps.Delete: %s", err)
	}
	return nil
}

func getSvcNATKey(svc k8sp.ServicePort) (nat.FrontendKey, error) {
	ip := svc.ClusterIP()
	port := svc.Port()
	proto, err := ProtoV1ToInt(svc.Protocol())
	if err != nil {
		return nat.FrontendKey{}, err
	}

	key := nat.NewNATKey(ip, uint16(port), proto)
	return key, nil
}

func getSvcNATKeyLBSrcRange(svc k8sp.ServicePort) ([]nat.FrontendKey, error) {
	var keys []nat.FrontendKey
	ipaddr := svc.ClusterIP()
	port := svc.Port()
	loadBalancerSourceRanges := svc.LoadBalancerSourceRanges()
	log.Debugf("loadbalancer %v", loadBalancerSourceRanges)
	proto, err := ProtoV1ToInt(svc.Protocol())
	if err != nil {
		return keys, err
	}
	for _, src := range loadBalancerSourceRanges {
		// Ignore IPv6 addresses
		if strings.Contains(src, ":") {
			continue
		}
		key := nat.NewNATKeySrc(ipaddr, uint16(port), proto, ip.MustParseCIDROrIP(src).(ip.V4CIDR))
		keys = append(keys, key)
	}
	return keys, nil
}

func (s *Syncer) writeLBSrcRangeSvcNATKeys(svc k8sp.ServicePort, svcID uint32, count, local int) error {
	var key nat.FrontendKey
	affinityTimeo := uint32(0)
	if svc.SessionAffinityType() == v1.ServiceAffinityClientIP {
		affinityTimeo = uint32(svc.StickyMaxAgeSeconds())
	}

	if len(svc.LoadBalancerSourceRanges()) == 0 {
		return nil
	}
	keys, err := getSvcNATKeyLBSrcRange(svc)
	if err != nil {
		return err
	}
	val := nat.NewNATValue(svcID, uint32(count), uint32(local), affinityTimeo)
	for _, key := range keys {
		log.Debugf("bpf map writing %s:%s", key, val)
		if err = s.bpfSvcs.Update(key[:], val[:]); err != nil {
			return errors.Errorf("bpfSvcs.Update: %s", err)
		}
	}
	key, err = getSvcNATKey(svc)
	if err != nil {
		return err
	}
	val = nat.NewNATValue(svcID, nat.BlackHoleCount, uint32(0), uint32(0))
	if err = s.bpfSvcs.Update(key[:], val[:]); err != nil {
		return errors.Errorf("bpfSvcs.Update: %s", err)
	}
	return nil
}

func (s *Syncer) writeSvc(svc k8sp.ServicePort, svcID uint32, count, local int) error {
	key, err := getSvcNATKey(svc)
	if err != nil {
		return err
	}

	affinityTimeo := uint32(0)
	if svc.SessionAffinityType() == v1.ServiceAffinityClientIP {
		affinityTimeo = uint32(svc.StickyMaxAgeSeconds())
	}

	val := nat.NewNATValue(svcID, uint32(count), uint32(local), affinityTimeo)

	log.Debugf("bpf map writing %s:%s", key, val)
	if err := s.bpfSvcs.Update(key[:], val[:]); err != nil {
		return errors.Errorf("bpfSvcs.Update: %s", err)
	}

	var affkey nat.FrontEndAffinityKey
	copy(affkey[:], key.Affinitykey())
	// we must have written the backends by now so the map exists
	if s.stickyEps[svcID] != nil {
		s.stickySvcs[affkey] = stickyFrontend{
			id:    svcID,
			timeo: time.Duration(affinityTimeo) * time.Second,
		}
	}

	return nil
}

func (s *Syncer) deleteSvc(svc k8sp.ServicePort, svcID uint32, count int) error {
	for i := 0; i < count; i++ {
		if err := s.deleteSvcBackend(svcID, uint32(i)); err != nil {
			return err
		}
	}

	key, err := getSvcNATKey(svc)
	if err != nil {
		return err
	}

	log.Debugf("bpf map deleting %s:%s", key, nat.NewNATValue(svcID, uint32(count), 0, 0))
	if err := s.bpfSvcs.Delete(key[:]); err != nil {
		return errors.WithMessage(err, "Delete svc")
	}

	keys, err := getSvcNATKeyLBSrcRange(svc)
	if err != nil {
		return err
	}
	for _, key := range keys {
		log.Debugf("bpf map deleting %s:%s", key, nat.NewNATValue(svcID, uint32(count), 0, 0))
		err := s.bpfSvcs.Delete(key[:])
		if err != nil && !bpf.IsNotExists(err) {
			return errors.WithMessage(err, "Delete svc")
		}
	}

	return nil
}

// ProtoV1ToInt translates k8s v1.Protocol to its IANA number and returns
// error if the proto is not recognized
func ProtoV1ToInt(p v1.Protocol) (uint8, error) {
	switch p {
	case v1.ProtocolTCP:
		return 6, nil
	case v1.ProtocolUDP:
		return 17, nil
	case v1.ProtocolSCTP:
		return 132, nil
	}

	return 0, errors.Errorf("unknown protocol %q", p)
}

// ProtoV1ToIntPanic translates k8s v1.Protocol to its IANA number and panics if
// the protocol is not recognized
func ProtoV1ToIntPanic(p v1.Protocol) uint8 {
	pn, err := ProtoV1ToInt(p)
	if err != nil {
		panic(err)
	}
	return pn
}

func (s *Syncer) newSvcID() uint32 {
	// TODO we may run out of IDs unless we restart ot recycle
	id := s.nextSvcID
	s.nextSvcID++
	return id
}

func (s *Syncer) matchBpfSvc(bsvc nat.FrontendKey, svcs k8sp.ServiceMap) *svcKey {
	for svc, info := range svcs {
		if bsvc.Proto() != ProtoV1ToIntPanic(info.Protocol()) {
			continue
		}

		matchNP := func() *svcKey {
			if bsvc.Port() == uint16(info.NodePort()) {
				for _, nip := range s.nodePortIPs {
					if bsvc.Addr().String() == nip.String() {
						skey := &svcKey{
							sname: svc,
							extra: getSvcKeyExtra(svcTypeNodePort, nip.String()),
						}
						log.Debugf("resolved %s as %s", bsvc, skey)
						return skey
					}
				}
			}

			return nil
		}

		if bsvc.Port() != uint16(info.Port()) {
			if sk := matchNP(); sk != nil {
				return sk
			}
			continue
		}
		matchLBSrcIp := func() bool {
			// External IP with zero Src CIDR is a valid entry and should not be considered
			// as stale
			if bsvc.SrcCIDR() == nat.ZeroCIDR {
				return true
			}
			// If the service does not have any source address range, treat all the entries with
			// src cidr as stale.
			if len(info.LoadBalancerSourceRanges()) == 0 {
				return false
			}
			// If the service does have source range specified, look for a match
			for _, srcip := range info.LoadBalancerSourceRanges() {
				if strings.Contains(srcip, ":") {
					continue
				}
				cidr := ip.MustParseCIDROrIP(srcip).(ip.V4CIDR)
				if cidr == bsvc.SrcCIDR() {
					return true
				}
			}
			return false
		}

		if bsvc.Addr().String() == info.ClusterIP().String() {
			if bsvc.SrcCIDR() == nat.ZeroCIDR {
				skey := &svcKey{
					sname: svc,
				}
				log.Debugf("resolved %s as %s", bsvc, skey)
				return skey
			}
		}

		for _, eip := range info.ExternalIPStrings() {
			if bsvc.Addr().String() == eip {
				if matchLBSrcIp() {
					skey := &svcKey{
						sname: svc,
						extra: getSvcKeyExtra(svcTypeExternalIP, eip),
					}
					log.Debugf("resolved %s as %s", bsvc, skey)
					return skey
				}
			}
		}

		// just in case the NodePort port is the same as the Port
		if sk := matchNP(); sk != nil {
			return sk
		}
	}

	return nil
}

func (s *Syncer) runExpandNPFixup(misses []*expandMiss) {
	s.expFixupStop = make(chan struct{})
	if len(misses) == 0 {
		return
	}
	s.expFixupWg.Add(1)

	// start the fixer routine and exit
	go func() {
		log.Debug("fixer started")
		defer s.expFixupWg.Done()
		defer log.Debug("fixer exited")
		s.mapsLck.Lock()
		defer s.mapsLck.Unlock()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// monitor if we should stop and if so, cancel any work
		go func() {
			select {
			case <-s.stop:
				cancel()
			case <-s.expFixupStop:
				cancel()
			case <-ctx.Done():
				// do nothing, we exited, work is done, just quit
			}
		}()

		for {
			log.Debugf("%d misses unresolved", len(misses))

			// We do one pass rightaway since we cannot know whether there
			// was an update or not before we got here
			s.rt.WaitAfter(ctx, func(lookup func(addr ip.Addr) (routes.Value, bool)) bool {
				var again []*expandMiss
				for _, m := range misses {
					if miss := s.expandNodePorts(m.sname, m.sinfo, m.eps, m.nport, lookup); miss != nil {
						again = append(again, miss)
					}
				}

				misses = again

				return len(misses) == 0 // block or not block
			})

			if len(misses) == 0 || ctx.Err() != nil {
				return
			}
		}
	}()
}

func (s *Syncer) stopExpandNPFixup() {
	close(s.expFixupStop)
	s.expFixupWg.Wait()
}

// Stop sto pthe syncer
func (s *Syncer) Stop() {
	s.stopOnce.Do(func() {
		close(s.stop)
		s.expFixupWg.Wait()
	})
}

func (s *Syncer) cleanupSticky() error {

	// no sticky service was updated, there cannot be any stale affinity entries
	// to clean up
	if len(s.stickySvcs) == 0 && !s.stickySvcDeleted {
		return nil
	}

	var (
		key nat.AffinityKey
		val nat.AffinityValue
	)

	dels := make([]nat.AffinityKey, 0, 64)
	ks := len(nat.AffinityKey{})
	vs := len(nat.AffinityValue{})

	now := time.Duration(bpf.KTimeNanos())

	err := s.bpfAff.Iter(func(k, v []byte) {

		copy(key[:], k[:ks])
		copy(val[:], v[:vs])

		fend, ok := s.stickySvcs[key.FrontendAffinityKey()]
		if !ok {
			log.Debugf("cleaning affinity %v:%v - no such a service", key, val)
			dels = append(dels, key)
			return
		}

		if _, ok := s.stickyEps[fend.id][val.Backend()]; !ok {
			log.Debugf("cleaning affinity %v:%v - no such a backend", key, val)
			dels = append(dels, key)
			return
		}

		if now-val.Timestamp() > fend.timeo {
			log.Debugf("cleaning affinity %v:%v - expired", key, val)
			dels = append(dels, key)
			return
		}
		log.Debugf("cleaning affinity %v:%v - keeping", key, val)
	})

	if err != nil {
		return errors.Errorf("NAT affinity map iterator failed: %s", err)
	}

	errs := 0

	for _, k := range dels {
		if err := s.bpfAff.Delete(k.AsBytes()); err != nil {
			log.WithField("key", k).Errorf("Failed to delete stale NAT affinity record")
		}
	}

	if errs > 0 {
		return errors.Errorf("encountered  %d errors writing NAT affinity map", errs)
	}
	return nil
}

func (s *Syncer) frontendHasBackend(ip net.IP, port uint16, backendIP net.IP, backendPort uint16, proto uint8) bool {
	id, ok := s.activeSvcsMap[ipPortProto{ipPort{ip.String(), int(port)}, proto}]
	if !ok {
		return false
	}

	backends := s.activeEpsMap[id]
	if backends == nil {
		return false
	}

	_, ok = backends[ipPort{backendIP.String(), int(backendPort)}]

	return ok
}

func serviceInfoFromK8sServicePort(sport k8sp.ServicePort) *serviceInfo {
	sinfo := new(serviceInfo)

	// create a shallow copy
	sinfo.clusterIP = sport.ClusterIP()
	sinfo.port = sport.Port()
	sinfo.protocol = sport.Protocol()
	sinfo.nodePort = sport.NodePort()
	sinfo.sessionAffinityType = sport.SessionAffinityType()
	sinfo.stickyMaxAgeSeconds = sport.StickyMaxAgeSeconds()
	sinfo.externalIPs = sport.ExternalIPStrings()
	sinfo.loadBalancerIPStrings = sport.LoadBalancerIPStrings()
	sinfo.loadBalancerSourceRanges = sport.LoadBalancerSourceRanges()
	sinfo.healthCheckNodePort = sport.HealthCheckNodePort()
	sinfo.onlyNodeLocalEndpoints = sport.OnlyNodeLocalEndpoints()
	sinfo.topologyKeys = sport.TopologyKeys()

	return sinfo
}

type serviceInfo struct {
	clusterIP                net.IP
	port                     int
	protocol                 v1.Protocol
	nodePort                 int
	sessionAffinityType      v1.ServiceAffinity
	stickyMaxAgeSeconds      int
	externalIPs              []string
	loadBalancerSourceRanges []string
	loadBalancerIPStrings    []string
	healthCheckNodePort      int
	onlyNodeLocalEndpoints   bool
	topologyKeys             []string
}

// TopologyKeys is part of ServicePort interface.
func (info *serviceInfo) TopologyKeys() []string {
	return info.topologyKeys
}

// String is part of ServicePort interface.
func (info *serviceInfo) String() string {
	return fmt.Sprintf("%s:%d/%s", info.clusterIP, info.port, info.protocol)
}

// ClusterIP is part of ServicePort interface.
func (info *serviceInfo) ClusterIP() net.IP {
	return info.clusterIP
}

// Port is part of ServicePort interface.
func (info *serviceInfo) Port() int {
	return info.port
}

// SessionAffinityType is part of the ServicePort interface.
func (info *serviceInfo) SessionAffinityType() v1.ServiceAffinity {
	return info.sessionAffinityType
}

// StickyMaxAgeSeconds is part of the ServicePort interface
func (info *serviceInfo) StickyMaxAgeSeconds() int {
	return info.stickyMaxAgeSeconds
}

// Protocol is part of ServicePort interface.
func (info *serviceInfo) Protocol() v1.Protocol {
	return info.protocol
}

// LoadBalancerSourceRanges is part of ServicePort interface
func (info *serviceInfo) LoadBalancerSourceRanges() []string {
	return info.loadBalancerSourceRanges
}

// HealthCheckNodePort is part of ServicePort interface.
func (info *serviceInfo) HealthCheckNodePort() int {
	return info.healthCheckNodePort
}

// NodePort is part of the ServicePort interface.
func (info *serviceInfo) NodePort() int {
	return info.nodePort
}

// ExternalIPStrings is part of ServicePort interface.
func (info *serviceInfo) ExternalIPStrings() []string {
	return info.externalIPs
}

// LoadBalancerIPStrings is part of ServicePort interface.
func (info *serviceInfo) LoadBalancerIPStrings() []string {
	return info.loadBalancerIPStrings
}

// OnlyNodeLocalEndpoints is part of ServicePort interface.
func (info *serviceInfo) OnlyNodeLocalEndpoints() bool {
	return info.onlyNodeLocalEndpoints
}

// K8sServicePortOption defines options for NewK8sServicePort
type K8sServicePortOption func(interface{})

// NewK8sServicePort creates a new k8s ServicePort
func NewK8sServicePort(clusterIP net.IP, port int, proto v1.Protocol,
	opts ...K8sServicePortOption) k8sp.ServicePort {

	x := &serviceInfo{
		clusterIP: clusterIP,
		port:      port,
		protocol:  proto,
	}

	for _, o := range opts {
		o(x)
	}
	return x
}

// ServicePortEqual compares if two k8sp.ServicePort are equal, that is all of
// their methods return equal values, i.e., they may differ in implementation,
// but present themselves equaly. String() is not considered as thay may differ
// for debugging reasons.
func ServicePortEqual(a, b k8sp.ServicePort) bool {
	return a.ClusterIP().Equal(b.ClusterIP()) &&
		a.Port() == b.Port() &&
		a.SessionAffinityType() == b.SessionAffinityType() &&
		a.StickyMaxAgeSeconds() == b.StickyMaxAgeSeconds() &&
		a.Protocol() == b.Protocol() &&
		a.HealthCheckNodePort() == b.HealthCheckNodePort() &&
		a.NodePort() == b.NodePort() &&
		a.OnlyNodeLocalEndpoints() == b.OnlyNodeLocalEndpoints() &&
		stringsEqual(a.ExternalIPStrings(), b.ExternalIPStrings()) &&
		stringsEqual(a.LoadBalancerIPStrings(), b.LoadBalancerIPStrings()) &&
		stringsEqual(a.LoadBalancerSourceRanges(), b.LoadBalancerSourceRanges()) &&
		stringsEqual(a.TopologyKeys(), b.TopologyKeys())
}

func stringsEqual(a, b []string) bool {

	if len(a) != len(b) {
		return false
	}

	sort.Strings(a)
	sort.Strings(b)

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

// K8sSvcWithLBSourceRangeIPs sets LBSourcePortRangeIPs
func K8sSvcWithLBSourceRangeIPs(ips []string) K8sServicePortOption {
	return func(s interface{}) {
		s.(*serviceInfo).loadBalancerSourceRanges = ips
	}
}

// K8sSvcWithExternalIPs sets ExternalIPs
func K8sSvcWithExternalIPs(ips []string) K8sServicePortOption {
	return func(s interface{}) {
		s.(*serviceInfo).externalIPs = ips
	}
}

// K8sSvcWithNodePort sets the nodeport
func K8sSvcWithNodePort(np int) K8sServicePortOption {
	return func(s interface{}) {
		s.(*serviceInfo).nodePort = np
	}
}

// K8sSvcWithLocalOnly sets OnlyNodeLocalEndpoints=true
func K8sSvcWithLocalOnly() K8sServicePortOption {
	return func(s interface{}) {
		s.(*serviceInfo).onlyNodeLocalEndpoints = true
	}
}

// K8sSvcWithStickyClientIP sets ServiceAffinityClientIP to seconds
func K8sSvcWithStickyClientIP(seconds int) K8sServicePortOption {
	return func(s interface{}) {
		s.(*serviceInfo).stickyMaxAgeSeconds = seconds
		s.(*serviceInfo).sessionAffinityType = v1.ServiceAffinityClientIP
	}
}
