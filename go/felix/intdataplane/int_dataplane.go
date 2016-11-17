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
	"github.com/projectcalico/felix/go/felix/proto"
)

func StartIntDataplaneDriver() *internalDataplane {
	dp := &internalDataplane{
		toDataplane:   make(chan interface{}, 100),
		fromDataplane: make(chan interface{}, 100),
	}
	go dp.loopUpdatingDataplane()
	go dp.loopReportingStatus()
	return dp
}

type internalDataplane struct {
	toDataplane   chan interface{}
	fromDataplane chan interface{}
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
		case *proto.IPSetUpdate:
			log.WithField("msg", msg).Warn("Message not implemented")
		case *proto.IPSetDeltaUpdate:
			log.WithField("msg", msg).Warn("Message not implemented")
		case *proto.IPSetRemove:
			log.WithField("msg", msg).Warn("Message not implemented")

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

}

func (d *internalDataplane) loopReportingStatus() {
	log.Info("Started internal status report thread")
	// TODO(smc) Implement status reporting.
}
