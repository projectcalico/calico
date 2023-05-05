// Copyright (c) 2017,2021 Tigera, Inc. All rights reserved.
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

package fvtests

import (
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

func NewRecorder() *StateRecorder {
	return &StateRecorder{
		kvs: map[string]api.Update{},
	}
}

// stateRecorder is our mock client callback, it records the updates it receives in a map.  When accessed via methods,
// all fields are protected by a mutex so it can be used with this construction:
//
//	Eventually(recorder.State).Should(Equal(...))
type StateRecorder struct {
	L             sync.Mutex
	status        api.SyncStatus
	kvs           map[string]api.Update
	err           error
	blockAfter    int
	blockDuration time.Duration
}

func (r *StateRecorder) KVs() map[string]api.Update {
	r.L.Lock()
	defer r.L.Unlock()

	kvsCpy := map[string]api.Update{}
	for k, v := range r.kvs {
		kvsCpy[k] = v
	}
	return kvsCpy
}

// Len returns the number of KVs that we've recorded.
func (r *StateRecorder) Len() int {
	r.L.Lock()
	defer r.L.Unlock()

	return len(r.kvs)
}

func (r *StateRecorder) Status() api.SyncStatus {
	r.L.Lock()
	defer r.L.Unlock()

	return r.status
}

func (r *StateRecorder) OnUpdates(updates []api.Update) {
	r.L.Lock()
	defer r.L.Unlock()

	for _, u := range updates {
		path, err := model.KeyToDefaultPath(u.Key)
		if err != nil {
			r.err = err
			continue
		}
		if u.Value == nil {
			delete(r.kvs, path)
		} else {
			r.kvs[path] = u
		}

		if r.blockAfter > 0 {
			r.blockAfter--
			if r.blockAfter == 0 {
				logrus.WithField("duration", r.blockDuration).Info("Recorder about to block")
				r.L.Unlock()
				time.Sleep(r.blockDuration)
				r.L.Lock()
				logrus.Info("Recorder woke up")
			}
		}
	}
}

func (r *StateRecorder) OnStatusUpdated(status api.SyncStatus) {
	r.L.Lock()
	defer r.L.Unlock()

	r.status = status
}

func (r *StateRecorder) BlockAfterNUpdates(n int, duration time.Duration) {
	r.L.Lock()
	defer r.L.Unlock()

	r.blockAfter = n
	r.blockDuration = duration
}
