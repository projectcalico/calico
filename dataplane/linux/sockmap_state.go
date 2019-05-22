// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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

	"github.com/projectcalico/felix/bpf"
	"github.com/projectcalico/felix/proto"
)

type sockmapState struct {
	bpfLib bpf.BPFDataplane
	cbIDs  []*CbID
}

func NewSockmapState() (*sockmapState, error) {
	lib, err := bpf.NewBPFLib()
	if err != nil {
		return nil, err
	}

	log.Debug("Created new Sockmap state.")
	return &sockmapState{
		bpfLib: lib,
		cbIDs:  nil,
	}, nil
}

func (s *sockmapState) PopulateCallbacks(cbs *callbacks) {
	cbIDs := []*CbID{
		cbs.UpdateWorkloadEndpointV4.Append(s.updateWorkload),
		cbs.RemoveWorkloadEndpointV4.Append(s.removeWorkload),
	}
	s.cbIDs = append(s.cbIDs, cbIDs...)
}

func (s *sockmapState) DepopulateCallbacks(cbs *callbacks) {
	for _, id := range s.cbIDs {
		cbs.Drop(id)
	}
	s.cbIDs = nil
}

func (s *sockmapState) updateWorkload(old, new *proto.WorkloadEndpoint) {
	if old != nil {
		for _, cidr := range old.Ipv4Nets {
			logCxt := log.WithField("cidr", cidr)
			ip, mask, err := bpf.MemberToIPMask(cidr)
			if err != nil {
				logCxt.WithError(err).Error("failed to convert cidr to ip and mask")
				return
			}

			if err := s.bpfLib.RemoveItemSockmapEndpointsMap(*ip, mask); err != nil {
				logCxt.WithError(err).Error("failed to remove item from endpoints map")
				return
			}

			log.Infof("[SOCKMAP] removed %v", cidr)
		}
	}
	for _, cidr := range new.Ipv4Nets {
		logCxt := log.WithField("cidr", cidr)

		ip, mask, err := bpf.MemberToIPMask(cidr)
		if err != nil {
			logCxt.WithError(err).Error("failed to convert cidr to ip and mask")
			return
		}

		if err := s.bpfLib.UpdateSockmapEndpoints(*ip, mask); err != nil {
			logCxt.WithError(err).Error("failed to update item on endpoints map")
			return
		}

		log.Infof("[SOCKMAP] added %v", cidr)
	}
}

func (s *sockmapState) removeWorkload(old *proto.WorkloadEndpoint) {
	for _, cidr := range old.Ipv4Nets {
		logCxt := log.WithField("cidr", cidr)
		ip, mask, err := bpf.MemberToIPMask(cidr)
		if err != nil {
			logCxt.WithError(err).Error("Failed to convert cidr to ip and mask.")
			return
		}

		if err := s.bpfLib.RemoveItemSockmapEndpointsMap(*ip, mask); err != nil {
			logCxt.WithError(err).Error("Failed to remove item from sockmap endpoints map.")
			return
		}
		logCxt.Debug("Workload CIDR removed from sockmap endpoints map.")
	}
}

func (s *sockmapState) SetupSockmapAcceleration() error {
	log.Debug("Setting up sockmap acceleration.")
	s.WipeSockmap()

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

func (s *sockmapState) WipeSockmap() {
	log.Debug("Wiping old sockmap state.")
	var err error
	err = s.bpfLib.DetachFromSockmap()
	if err != nil {
		log.WithError(err).Debug("Failed to detach sk_msg program from sockmap.")
	}
	err = s.bpfLib.DetachFromCgroup()
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
	err = s.bpfLib.RemoveSockmap()
	if err != nil {
		log.WithError(err).Debug("Failed to remove sockmap program.")
	}
}
