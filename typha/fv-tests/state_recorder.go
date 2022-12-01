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
	"context"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

func NewRecorder() *StateRecorder {
	return NewRecorderChanSize(1000)
}

func NewRecorderChanSize(n int) *StateRecorder {
	return &StateRecorder{
		kvs: map[string]api.Update{},
		c:   make(chan any, n),
	}
}

// stateRecorder is our mock client callback, it records the updates it receives in a map.  When accessed via methods,
// all fields are protected by a mutex so it can be used with this construction:
//
//     Eventually(recorder.State).Should(Equal(...))
type StateRecorder struct {
	L             sync.Mutex
	status        api.SyncStatus
	kvs           map[string]api.Update
	err           error
	blockAfter    int
	blockDuration time.Duration

	c chan any
}

func (r *StateRecorder) Loop(ctx context.Context) {
	for ctx.Err() == nil {
		select {
		case <-ctx.Done():
			return
		case msg := <-r.c:
			switch msg := msg.(type) {
			case api.SyncStatus:
				r.handleStatus(msg)
			case []api.Update:
				r.handleUpdates(msg)
			default:
				panic(msg)
			}
		}
	}
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
	r.c <- updates
}

func (r *StateRecorder) handleUpdates(updates []api.Update) {
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
				logrus.WithField("duration", r.blockDuration).Info("----- Recorder about to block")
				r.L.Unlock()
				time.Sleep(r.blockDuration)
				r.L.Lock()
				logrus.Info("----- Recorder woke up")
			}
		}
	}
}

func (r *StateRecorder) OnStatusUpdated(status api.SyncStatus) {
	r.c <- status
}

func (r *StateRecorder) handleStatus(msg api.SyncStatus) {
	r.L.Lock()
	defer r.L.Unlock()
	r.status = msg
}

func (r *StateRecorder) BlockAfterNUpdates(n int, duration time.Duration) {
	r.L.Lock()
	defer r.L.Unlock()

	r.blockAfter = n
	r.blockDuration = duration
}

func (r *StateRecorder) KVCompareFn(kvs map[string]api.Update) func() error {
	return func() error {
		r.L.Lock()
		defer r.L.Unlock()

		if len(r.kvs) != len(kvs) {
			return fmt.Errorf("expected to receive %d KVs but only received %d KVs", len(kvs), len(r.kvs))
		}
		for k, v := range kvs {
			if v2, ok := r.kvs[k]; !ok {
				return fmt.Errorf("expected to receive key %q but did not", k)
			} else if !reflect.DeepEqual(v, v2) {
				return fmt.Errorf("key %q had value %v but expected %v", k, v2, v)
			}
		}
		return nil
	}
}
