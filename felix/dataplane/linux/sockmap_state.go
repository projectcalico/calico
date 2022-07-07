// Copyright (c) 2019-2021 Tigera, Inc. All rights reserved.
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
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/dataplane/common"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type sockmapState struct {
	bpfLib            bpf.BPFDataplane
	cbIDs             []*common.CbID
	workloadEndpoints map[string][]string // name -> []CIDR
}

func NewSockmapState() (*sockmapState, error) {
	lib, err := bpf.NewBPFLib("/usr/lib/calico/bpf/")
	if err != nil {
		return nil, err
	}

	log.Debug("Created new Sockmap state.")
	return &sockmapState{
		bpfLib:            lib,
		cbIDs:             nil,
		workloadEndpoints: make(map[string][]string),
	}, nil
}

func (s *sockmapState) PopulateCallbacks(cbs *common.Callbacks) {
	cbIDs := []*common.CbID{
		cbs.UpdateWorkloadEndpointV4.Append(s.updateWorkload),
		cbs.RemoveWorkloadEndpointV4.Append(s.removeWorkload),
	}
	s.cbIDs = append(s.cbIDs, cbIDs...)
}

func (s *sockmapState) DepopulateCallbacks(cbs *common.Callbacks) {
	for _, id := range s.cbIDs {
		cbs.Drop(id)
	}
	s.cbIDs = nil
}

func (s *sockmapState) flattenWorkloadEndpoints() set.Set[string] {
	wep := set.New[string]()
	for _, nets := range s.workloadEndpoints {
		for _, net := range nets {
			wep.Add(net)
		}
	}

	return wep
}

func (s *sockmapState) updateWorkload(old, new *proto.WorkloadEndpoint) {
	s.workloadEndpoints[new.Name] = new.Ipv4Nets

	desired := s.flattenWorkloadEndpoints()

	if err := s.processWorkloadUpdates(desired); err != nil {
		log.WithError(err).Error("failed to process workload updates")
		return
	}
}

func (s *sockmapState) processWorkloadUpdates(desired set.Set[string]) error {
	current := set.New[string]()

	cidrs, err := s.bpfLib.DumpSockmapEndpointsMap(bpf.IPFamilyV4)
	if err != nil {
		return err
	}

	for _, rawCIDR := range cidrs {
		ipnet := rawCIDR.ToIPNet()
		current.Add(ipnet.String())
	}

	toAdd := setDifference[string](desired, current)
	toDrop := setDifference[string](current, desired)

	toDrop.Iter(func(cidr string) error {
		logCxt := log.WithField("cidr", cidr)

		ip, mask, err := bpf.MemberToIPMask(cidr)
		if err != nil {
			logCxt.WithError(err).Error("failed to convert cidr to ip and mask")
			return set.StopIteration
		}

		if err := s.bpfLib.RemoveItemSockmapEndpointsMap(*ip, mask); err != nil {
			logCxt.WithError(err).Error("failed to remove item from endpoints map")
			return set.StopIteration
		}

		log.Infof("[SOCKMAP] removed %v", cidr)

		return nil
	})

	toAdd.Iter(func(cidr string) error {
		logCxt := log.WithField("cidr", cidr)

		ip, mask, err := bpf.MemberToIPMask(cidr)
		if err != nil {
			logCxt.WithError(err).Error("failed to convert cidr to ip and mask")
			return set.StopIteration
		}

		if err := s.bpfLib.UpdateSockmapEndpoints(*ip, mask); err != nil {
			logCxt.WithError(err).Error("failed to update item on endpoints map")
			return set.StopIteration
		}

		log.Infof("[SOCKMAP] added %v", cidr)

		return nil
	})

	return nil
}

func (s *sockmapState) removeWorkload(old *proto.WorkloadEndpoint) {
	delete(s.workloadEndpoints, old.Name)

	desired := s.flattenWorkloadEndpoints()

	if err := s.processWorkloadUpdates(desired); err != nil {
		log.WithError(err).Error("failed to process workload updates")
		return
	}
}

func (s *sockmapState) SetupSockmapAcceleration() error {
	log.Debug("Setting up sockmap acceleration.")
	s.WipeSockmap(bpf.FindByID)

	log.Debug("Creating sockmap map.")
	if _, err := s.bpfLib.NewSockmap(); err != nil {
		return err
	}

	log.Debug("Creating sockmap endpoints map.")
	if _, err := s.bpfLib.NewSockmapEndpointsMap(); err != nil {
		return err
	}

	log.Debug("Loading sockops program.")
	if err := s.bpfLib.LoadSockopsAuto(); err != nil {
		return err
	}

	log.Debug("Loading sk_msg program.")
	if err := s.bpfLib.LoadSkMsgAuto(); err != nil {
		return err
	}

	log.Debug("Attaching sk_msg program to sockmap.")
	if err := s.bpfLib.AttachToSockmap(); err != nil {
		return err
	}

	log.Debug("Attaching sockops program to cgroup.")
	if err := s.bpfLib.AttachToCgroup(); err != nil {
		return err
	}

	return nil
}

func (s *sockmapState) WipeSockmap(mode bpf.FindObjectMode) {
	log.Debug("Wiping old sockmap state.")
	err := s.bpfLib.DetachFromSockmap(mode)
	if err != nil {
		log.WithError(err).Debug("Failed to detach sk_msg program from sockmap.")
	}
	err = s.bpfLib.DetachFromCgroup(mode)
	if err != nil {
		log.WithError(err).Debug("Failed to detach sockops program from cgroup.")
	}
	err = s.bpfLib.RemoveSockops()
	if err != nil {
		log.WithError(err).Debug("Failed to remove sockops program.")
	}
	err = s.bpfLib.RemoveSkMsg()
	if err != nil {
		log.WithError(err).Debug("Failed to remove sk_msg program.")
	}
	err = s.bpfLib.RemoveSockmapEndpointsMap()
	if err != nil {
		log.WithError(err).Debug("Failed to remove sockmap endpoints map.")
	}
	err = s.bpfLib.RemoveSockmap(mode)
	if err != nil {
		log.WithError(err).Debug("Failed to remove sockmap program.")
	}
}
