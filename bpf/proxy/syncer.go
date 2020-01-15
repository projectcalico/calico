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
	"strconv"
	"strings"
	"time"

	"github.com/projectcalico/felix/bpf/nat"

	"github.com/pkg/errors"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	k8sp "k8s.io/kubernetes/pkg/proxy"

	"github.com/projectcalico/felix/bpf"
	"github.com/projectcalico/felix/bpf/routes"
	"github.com/projectcalico/felix/ip"
)

var podNPIP = net.IPv4(255, 255, 255, 255)

const rtUpdateDelayMax = 200 * time.Millisecond

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

// Syncer is an implementation of DPSyncer interface. It is not thread safe and
// should be called only once at a time
type Syncer struct {
	bpfSvcs bpf.Map
	bpfEps  bpf.Map

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

	// synced is true after reconciling the first Apply
	synced bool
	// origs are deallocated after the first Apply reconciles
	origSvcs nat.MapMem
	origEps  nat.BackendMapMem
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

// NewSyncer returns a new Syncer that uses the 2 provided maps
func NewSyncer(nodePortIPs []net.IP, svcsmap, epsmap bpf.Map, rt Routes) (*Syncer, error) {
	s := &Syncer{
		bpfSvcs:     svcsmap,
		bpfEps:      epsmap,
		rt:          rt,
		nodePortIPs: uniqueIPs(nodePortIPs),
		prevSvcMap:  make(map[svcKey]svcInfo),
		prevEpsMap:  make(k8sp.EndpointsMap),
	}

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

			log.Debugf("bpf map deleting derived %s:%s", key, nat.NewNATValue(id, 0, 0))
			if err := s.bpfSvcs.Delete(key[:]); err != nil {
				return errors.Errorf("bpfSvcs.Delete: %s", err)
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
		if old.svc == sinfo {
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

	log.Debugf("applied a service %s update: sinfo=%+v", skey, s.newSvcMap[skey])

	return nil
}

func (s *Syncer) getRoute(addr ip.V4Addr) (routes.Value, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rtUpdateDelayMax)
	defer cancel()
	v, ok := s.rt.Lookup(ctx, addr)
	if !ok {
		return routes.Value{}, errors.Errorf("no route for %s", addr)
	}

	return v, nil
}

func (s *Syncer) expandNodePorts(sname k8sp.ServicePortName, sinfo k8sp.ServicePort,
	eps []k8sp.Endpoint, nport int) {

	m := make(map[ip.V4Addr][]k8sp.Endpoint)

	for _, ep := range eps {
		ipv4 := ip.FromString(ep.IP()).(ip.V4Addr)

		rt, err := s.getRoute(ipv4)
		if err != nil {
			log.WithField("error", err).Error("Missing route")
			continue
		}

		nodeIP := rt.NextHop().(ip.V4Addr)

		m[nodeIP] = append(m[nodeIP], ep)
	}

	for node, neps := range m {
		skey := getSvcKey(sname, getSvcKeyExtra(svcTypeNodePortRemote, node.String()))
		si := *(sinfo.(*k8sp.BaseServiceInfo))
		si.ClusterIP = node.AsNetIP()
		si.Port = nport
		if err := s.applySvc(skey, &si, neps, nil); err != nil {
			log.Errorf("Failed to expand NodePort for %s node %s", sname, node)
			continue
		}
	}
}

func (s *Syncer) applyDerived(sname k8sp.ServicePortName, t svcType, sinfo k8sp.ServicePort) error {

	svc, ok := s.newSvcMap[getSvcKey(sname, "")]
	if !ok {
		// this should not happend
		return errors.Errorf("no ClusterIP for derived service type %d", t)
	}

	var skey svcKey
	count := svc.count
	local := svc.localCount

	skey = getSvcKey(sname, getSvcKeyExtra(t, sinfo.ClusterIPString()))
	switch t {
	case svcTypeNodePort:
		if sinfo.(*k8sp.BaseServiceInfo).OnlyNodeLocalEndpoints {
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

	// insert or update existing services
	for sname, sinfo := range state.SvcMap {
		skey := getSvcKey(sname, "")
		eps := state.EpsMap[sname]
		if err := s.applySvc(skey, sinfo, eps, s.cleanupDerived); err != nil {
			return err
		}

		// N.B. we assume that k8s provide us with no duplicities
		for _, extIP := range sinfo.ExternalIPStrings() {
			extInfo := *(sinfo.(*k8sp.BaseServiceInfo))
			extInfo.ClusterIP = net.ParseIP(extIP)
			if extInfo.ClusterIP == nil {
				log.Errorf("failed to parse ExternalIP %s for service %s", extIP, sname)
				continue
			}
			err := s.applyDerived(sname, svcTypeExternalIP, &extInfo)
			if err != nil {
				log.Errorf("failed to apply ExternalIP %s for service %s : %s", extIP, sname, err)
				continue
			}
		}

		if nport := sinfo.GetNodePort(); nport != 0 {
			bi := sinfo.(*k8sp.BaseServiceInfo)
			onlyRemotes := bi.OnlyNodeLocalEndpoints && s.newSvcMap[skey].localCount == 0
			for _, npip := range s.nodePortIPs {
				npInfo := *bi
				npInfo.ClusterIP = npip
				npInfo.Port = nport
				if npip.Equal(podNPIP) && onlyRemotes {
					// do not program the meta entry, program each node
					// separately
					continue
				}
				err := s.applyDerived(sname, svcTypeNodePort, &npInfo)
				if err != nil {
					log.Errorf("failed to apply NodePort %s for service %s : %s", npip, sname, err)
					continue
				}
			}
			if onlyRemotes {
				s.expandNodePorts(sname, sinfo, eps, nport)
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

		log.Infof("removed stale service %q", skey)
	}

	s.prevSvcMap = s.newSvcMap
	s.prevEpsMap = s.newEpsMap

	log.Debugf("new state written")
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
	}
	return s.apply(state)
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
	ip := net.ParseIP(svc.ClusterIPString())
	if ip == nil {
		return nat.FrontendKey{}, errors.Errorf("failed to parse ClusterIP %q", svc.ClusterIPString())
	}
	// XXX will fail if we change the type, 1.16 provides ServicePort.Port()
	port := svc.(*k8sp.BaseServiceInfo).Port
	proto, err := protoV1ToInt(svc.GetProtocol())
	if err != nil {
		return nat.FrontendKey{}, err
	}

	key := nat.NewNATKey(ip, uint16(port), proto)

	return key, nil
}

func (s *Syncer) writeSvc(svc k8sp.ServicePort, svcID uint32, count, local int) error {
	key, err := getSvcNATKey(svc)
	if err != nil {
		return err
	}

	val := nat.NewNATValue(svcID, uint32(count), uint32(local))

	log.Debugf("bpf map writing %s:%s", key, val)
	if err := s.bpfSvcs.Update(key[:], val[:]); err != nil {
		return errors.Errorf("bpfSvcs.Update: %s", err)
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

	log.Debugf("bpf map deleting %s:%s", key, nat.NewNATValue(svcID, uint32(count), 0))
	if err := s.bpfSvcs.Delete(key[:]); err != nil {
		return errors.Errorf("bpfSvcs.Delete: %s", err)
	}

	return nil
}

func protoV1ToInt(p v1.Protocol) (uint8, error) {
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
	pn, err := protoV1ToInt(p)
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
		if bsvc.Proto() != ProtoV1ToIntPanic(info.GetProtocol()) {
			continue
		}

		matchNP := func() *svcKey {
			if bsvc.Port() == uint16(info.GetNodePort()) {
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

		if bsvc.Port() != uint16(info.(*k8sp.BaseServiceInfo).Port) {
			if sk := matchNP(); sk != nil {
				return sk
			}
			continue
		}

		if bsvc.Addr().String() == info.ClusterIPString() {
			skey := &svcKey{
				sname: svc,
			}
			log.Debugf("resolved %s as %s", bsvc, skey)
			return skey
		}

		for _, eip := range info.ExternalIPStrings() {
			if bsvc.Addr().String() == eip {
				skey := &svcKey{
					sname: svc,
					extra: getSvcKeyExtra(svcTypeExternalIP, eip),
				}
				log.Debugf("resolved %s as %s", bsvc, skey)
				return skey
			}
		}

		// just in case the NodePort port is the same as the Port
		if sk := matchNP(); sk != nil {
			return sk
		}
	}

	return nil
}
