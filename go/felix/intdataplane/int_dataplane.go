// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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
	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/felix/go/felix/ipsets"
	"github.com/projectcalico/felix/go/felix/iptables"
	"github.com/projectcalico/felix/go/felix/proto"
)

func StartIntDataplaneDriver() *internalDataplane {
	dp := &internalDataplane{
		toDataplane:   make(chan interface{}, 100),
		fromDataplane: make(chan interface{}, 100),
		filterTableV4: iptables.NewTable("filter", 4),
		filterTableV6: iptables.NewTable("filter", 6),
		ipsetsV4:      ipsets.NewIPSets(ipsets.IPFamilyV4),
		ipsetsV6:      ipsets.NewIPSets(ipsets.IPFamilyV6),
	}
	go dp.loopUpdatingDataplane()
	go dp.loopReportingStatus()
	return dp
}

type internalDataplane struct {
	toDataplane   chan interface{}
	fromDataplane chan interface{}

	filterTableV4 *iptables.Table
	filterTableV6 *iptables.Table

	ipsetsV4 *ipsets.IPSets
	ipsetsV6 *ipsets.IPSets
}

func (d *internalDataplane) SendMessage(msg interface{}) error {
	d.toDataplane <- msg
	return nil
}

func (d *internalDataplane) RecvMessage() (interface{}, error) {
	return <-d.fromDataplane, nil
}

func (d *internalDataplane) loopUpdatingDataplane() {
	log.Info("Started internal iptables dataplane driver")
	inSync := false
	for msg := range d.toDataplane {
		log.WithField("msg", msg).Info("Received update from calculation graph")
		switch msg := msg.(type) {
		// IP set-related messages, these are extremely common.
		case *proto.IPSetDeltaUpdate:
			// TODO(smc) Feels ugly to do the fan-out here.
			d.ipsetsV4.AddIPsToIPSet(msg.Id, msg.AddedMembers)
			d.ipsetsV4.RemoveIPsFromIPSet(msg.Id, msg.RemovedMembers)
			d.ipsetsV6.AddIPsToIPSet(msg.Id, msg.AddedMembers)
			d.ipsetsV6.RemoveIPsFromIPSet(msg.Id, msg.RemovedMembers)
		case *proto.IPSetUpdate:
			d.ipsetsV4.CreateOrReplaceIPSet(ipsets.IPSetMetadata{
				Type:     ipsets.IPSetTypeHashIP,
				SetID:    msg.Id,
				IPFamily: ipsets.IPFamilyV4,
				MaxSize:  1024 * 1024,
			}, msg.Members)
			d.ipsetsV6.CreateOrReplaceIPSet(ipsets.IPSetMetadata{
				Type:     ipsets.IPSetTypeHashIP,
				SetID:    msg.Id,
				IPFamily: ipsets.IPFamilyV6,
				MaxSize:  1024 * 1024,
			}, msg.Members)
		case *proto.IPSetRemove:
			d.ipsetsV4.RemoveIPSet(msg.Id)
			d.ipsetsV6.RemoveIPSet(msg.Id)

		// Local workload updates.
		case *proto.WorkloadEndpointUpdate:
			log.WithField("msg", msg).Warn("Message not implemented")
		case *proto.WorkloadEndpointRemove:
			log.WithField("msg", msg).Warn("Message not implemented")

		// Local host endpoint updates.
		case *proto.HostEndpointUpdate:
			log.WithField("msg", msg).Warn("Message not implemented")
		case *proto.HostEndpointRemove:
			log.WithField("msg", msg).Warn("Message not implemented")

		// Local active policy updates.
		case *proto.ActivePolicyUpdate:
			log.WithField("msg", msg).Warn("Message not implemented")
		case *proto.ActivePolicyRemove:
			log.WithField("msg", msg).Warn("Message not implemented")

		case *proto.ActiveProfileUpdate:
			log.WithField("msg", msg).Warn("Message not implemented")
		case *proto.ActiveProfileRemove:
			log.WithField("msg", msg).Warn("Message not implemented")

		// Less common cluster config updates.
		case *proto.HostMetadataUpdate:
			log.WithField("msg", msg).Warn("Message not implemented")
		case *proto.HostMetadataRemove:
			log.WithField("msg", msg).Warn("Message not implemented")
		case *proto.IPAMPoolUpdate:
			log.WithField("msg", msg).Warn("Message not implemented")
		case *proto.IPAMPoolRemove:
			log.WithField("msg", msg).Warn("Message not implemented")

		case *proto.ConfigUpdate:
			// Since we're in-process, we get our config from the typed config object.
			log.Debug("Ignoring config update")
		case *proto.InSync:
			log.Info("Datastore in sync, flushing the dataplane for the first time...")
			inSync = true
		default:
			log.WithField("msg", msg).Panic("Unknown message type")
		}

		if inSync {
			d.flush()
		}
	}
}

func (d *internalDataplane) flush() {
	d.ipsetsV4.ApplyUpdates()
	d.ipsetsV6.ApplyUpdates()

	d.filterTableV4.Apply()
	d.filterTableV6.Apply()

	d.ipsetsV4.ApplyDeletions()
	d.ipsetsV6.ApplyDeletions()
}

func (d *internalDataplane) loopReportingStatus() {
	log.Info("Started internal status report thread")
	// TODO(smc) Implement status reporting.
}
