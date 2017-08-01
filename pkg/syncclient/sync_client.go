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
	"context"
	"encoding/gob"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/typha/pkg/syncproto"
)

var nextID uint64

func New(addr string, myVersion, myHostname, myInfo string, cbs api.SyncerCallbacks) *SyncerClient {
	id := nextID
	nextID++
	return &SyncerClient{
		ID:        id,
		logCxt:    log.WithField("connID", id),
		callbacks: cbs,
		addr:      addr,

		myVersion:  myVersion,
		myHostname: myHostname,
		myInfo:     myInfo,
	}
}

type SyncerClient struct {
	ID                            uint64
	logCxt                        *log.Entry
	callbacks                     api.SyncerCallbacks
	addr                          string
	myHostname, myVersion, myInfo string
	c                             net.Conn
	Finished                      sync.WaitGroup
}

func (s *SyncerClient) Start(cxt context.Context) error {
	// Connect synchronously.
	err := s.connect(cxt)
	if err != nil {
		return err
	}

	// Then start our background goroutines.  We start the main loop and a second goroutine to
	// manage shutdown.
	cxt, cancelFn := context.WithCancel(cxt)
	s.Finished.Add(1)
	go s.loop(cxt, cancelFn)

	s.Finished.Add(1)
	go func() {
		// Wait for the context to finish, either due to external cancel or our own loop
		// exiting.
		<-cxt.Done()
		s.logCxt.Info("Typha client Context asked us to exit")
		// Close the connection.  This will trigger the main loop to exit if it hasn't
		// already.
		err := s.c.Close()
		if err != nil {
			log.WithError(err).Warn("Ignoring error from Close during shut-down of client.")
		}
		// Broadcast that we're finished.
		s.Finished.Done()
	}()
	return nil
}

func (s *SyncerClient) connect(cxt context.Context) error {
	log.Info("Starting Typha client")
	var err error
	logCxt := s.logCxt.WithField("address", s.addr)
	for cxt.Err() == nil {
		logCxt.Info("Connecting to Typha.")
		s.c, err = net.DialTimeout("tcp", s.addr, 10*time.Second)
		if err != nil {
			log.WithError(err).Error("Failed to connect to Typha, retrying...")
			time.Sleep(2 * time.Second)
			continue
		}
		break
	}
	if cxt.Err() != nil {
		if s.c != nil {
			err := s.c.Close()
			if err != nil {
				log.WithError(err).Warn("Ignoring error from Close during shut-down of client.")
			}
		}
		return cxt.Err()
	}
	logCxt.Info("Connected to Typha.")
	return nil
}

func (s *SyncerClient) onConnectionFailed(cxt context.Context, logCxt *log.Entry, err error, operation string) {
	if cxt.Err() != nil {
		logCxt.WithError(err).Warn("Connection failed while being shut down by context.")
		return
	}
	logCxt.WithError(err).Errorf("Failed to %s", operation)
}

func (s *SyncerClient) loop(cxt context.Context, cancelFn context.CancelFunc) {
	defer s.Finished.Done()
	defer cancelFn()

	logCxt := s.logCxt.WithField("address", s.addr)
	logCxt.Info("Started Typha client main loop")

	w := gob.NewEncoder(s.c)
	r := gob.NewDecoder(s.c)

	err := w.Encode(syncproto.Envelope{
		Message: syncproto.MsgClientHello{
			Hostname: s.myHostname,
			Version:  s.myVersion,
			Info:     s.myInfo,
		},
	})
	if err != nil {
		s.onConnectionFailed(cxt, logCxt, err, "write hello to server")
		return
	}

	for cxt.Err() == nil {
		var envelope syncproto.Envelope
		err := r.Decode(&envelope)
		if err != nil {
			s.onConnectionFailed(cxt, logCxt, err, "read from server")
			return
		}
		logCxt.WithField("envelope", envelope).Debug("New message from Typha.")
		switch msg := envelope.Message.(type) {
		case syncproto.MsgSyncStatus:
			logCxt.WithField("newStatus", msg.SyncStatus).Info(
				"Status update from Typha.")
			s.callbacks.OnStatusUpdated(msg.SyncStatus)
		case syncproto.MsgPing:
			logCxt.Debug("Ping received from Typha")
			err := w.Encode(syncproto.Envelope{Message: syncproto.MsgPong{
				PingTimestamp: msg.Timestamp,
			}})
			if err != nil {
				s.onConnectionFailed(cxt, logCxt, err, "write pong to server")
				return
			}
			logCxt.Debug("Pong sent to Typha")
		case syncproto.MsgKVs:
			updates := make([]api.Update, 0, len(msg.KVs))
			for _, kv := range msg.KVs {
				update, err := kv.ToUpdate()
				if err != nil {
					logCxt.WithError(err).Error("Failed to deserialize update, skipping.")
					continue
				}
				logCxt.WithFields(log.Fields{
					"serialized":   kv,
					"deserialized": update,
				}).Debug("Decoded update from Typha")
				updates = append(updates, update)
			}
			s.callbacks.OnUpdates(updates)
		case syncproto.MsgServerHello:
			logCxt.WithField("serverVersion", msg.Version).Info(
				"Server hello message received")
		}
	}
}
