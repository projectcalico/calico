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

package main

import (
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/typha/pkg/syncclient"
)

type syncerCallbacks struct{}

func (s *syncerCallbacks) OnStatusUpdated(status api.SyncStatus) {
	log.WithField("status", status).Info("Status received")
}

func (s *syncerCallbacks) OnUpdates(updates []api.Update) {
	log.WithField("numUpdates", len(updates)).Info("Updates received")
}

func main() {
	callbacks := &syncerCallbacks{}
	client := syncclient.New("127.0.0.1", "test-host", "some info", callbacks)
	client.Start()
	for {
		time.Sleep(10 * time.Second)
	}
}
