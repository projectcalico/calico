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
	"strconv"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/projectcalico/typha/pkg/buildinfo"
	"github.com/projectcalico/typha/pkg/syncproto"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
)

func New(addr string, myHostname, myInfo string, cbs api.SyncerCallbacks) *SyncerClient {
	return &SyncerClient{
		callbacks: cbs,
		addr:      addr,

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
	parts := strings.Split(s.addr, ":")
	var port int = syncproto.DefaultPort
	if len(parts) > 1 {
		var err error
		port, err = strconv.Atoi(parts[1])
		if err != nil {
			log.WithError(err).Panic("Failed to parse port")
		}
	}

	var err error
	var c *net.TCPConn
	logCxt := log.WithFields(log.Fields{
		"address": parts[0],
		"port":    port,
	})
	for {
		logCxt.Info("Connecting to Typha.")
		c, err = net.DialTCP("tcp",
			nil,
			&net.TCPAddr{
				IP:   net.ParseIP(parts[0]),
				Port: port,
			},
		)
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
			Version:  buildinfo.GitVersion,
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

		switch msg := envelope.Message.(type) {
		case syncproto.MsgSyncStatus:
			logCxt.WithField("newStatus", msg.SyncStatus).Info(
				"Status update from Typha.")
			s.callbacks.OnStatusUpdated(msg.SyncStatus)
		case syncproto.MsgPing:
			log.Info("Ping received from Typha")
			err := w.Encode(syncproto.Envelope{Message: syncproto.MsgPong{
				PingTimestamp: msg.Timestamp,
			}})
			if err != nil {
				log.WithError(err).Panic("Failed to write to server")
			}
			log.Info("Pong sent to Typha")
		case syncproto.MsgKVs:
			updates := make([]api.Update, len(msg.KVs))
			for i, kv := range msg.KVs {
				updates[i] = kv.ToUpdate()
			}
			s.callbacks.OnUpdates(updates)
		case syncproto.MsgServerHello:
			log.WithField("serverVersion", msg.Version).Info(
				"Server hello message received")
		}
	}
}
