// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

package syncclient

import (
	"encoding/gob"
	"net"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/typha/pkg/syncproto"
)

func New(addr string, myVersion, myHostname, myInfo string, cbs api.SyncerCallbacks) *SyncerClient {
	return &SyncerClient{
		callbacks: cbs,
		addr:      addr,

		myVersion:  myVersion,
		myHostname: myHostname,
		myInfo:     myInfo,
	}
}

type SyncerClient struct {
	callbacks                     api.SyncerCallbacks
	addr                          string
	myHostname, myVersion, myInfo string
}

func (s *SyncerClient) Start() {
	go s.loop()
}

func (s *SyncerClient) loop() {
	log.Info("Starting Typha client")
	var err error
	var c net.Conn
	logCxt := log.WithField("address", s.addr)
	for {
		logCxt.Info("Connecting to Typha.")
		c, err = net.DialTimeout("tcp", s.addr, 10*time.Second)
		if err != nil {
			log.WithError(err).Error("Failed to connect to Typha, retrying...")
			time.Sleep(2 * time.Second)
			continue
		}
		break
	}
	defer c.Close()
	logCxt.Info("Connected to Typha.")

	w := gob.NewEncoder(c)
	r := gob.NewDecoder(c)

	err = w.Encode(syncproto.Envelope{
		Message: syncproto.MsgClientHello{
			Hostname: s.myHostname,
			Version:  s.myVersion,
			Info:     s.myInfo,
		},
	})
	if err != nil {
		log.WithError(err).Panic("Failed to write hello to server")
	}

	for {
		var envelope syncproto.Envelope
		err := r.Decode(&envelope)
		if err != nil {
			log.WithError(err).Panic("Failed to read from server")
		}
		log.WithField("envelope", envelope).Debug("New message from Typha.")
		switch msg := envelope.Message.(type) {
		case syncproto.MsgSyncStatus:
			logCxt.WithField("newStatus", msg.SyncStatus).Info(
				"Status update from Typha.")
			s.callbacks.OnStatusUpdated(msg.SyncStatus)
		case syncproto.MsgPing:
			log.Debug("Ping received from Typha")
			err := w.Encode(syncproto.Envelope{Message: syncproto.MsgPong{
				PingTimestamp: msg.Timestamp,
			}})
			if err != nil {
				log.WithError(err).Panic("Failed to write to server")
			}
			log.Debug("Pong sent to Typha")
		case syncproto.MsgKVs:
			updates := make([]api.Update, len(msg.KVs))
			for i, kv := range msg.KVs {
				updates[i] = kv.ToUpdate()
				log.WithFields(log.Fields{
					"serialized":   kv,
					"deserialized": updates[i],
				}).Debug("Decoded update from Typha")
			}
			s.callbacks.OnUpdates(updates)
		case syncproto.MsgServerHello:
			log.WithField("serverVersion", msg.Version).Info(
				"Server hello message received")
		}
	}
}
