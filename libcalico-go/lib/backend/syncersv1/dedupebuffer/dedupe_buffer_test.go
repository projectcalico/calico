// Copyright (c) 2023 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dedupebuffer

import (
	"fmt"
	"sync"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

func init() {
	logrus.AddHook(&logutils.ContextHook{})
	logrus.SetFormatter(&logutils.Formatter{})
	logrus.SetLevel(logrus.DebugLevel)
}

func TestDedupeBuffer_SyncNoDupes(t *testing.T) {
	for _, onUpdatesVersion := range []string{"KeysKnown", "KeysNotKnown"} {
		t.Run(onUpdatesVersion, func(t *testing.T) {
			RegisterTestingT(t)
			d := New()
			onUpdates := wrapOnUpdates(d, onUpdatesVersion)
			rec := NewReceiver()

			d.OnStatusUpdated(api.WaitForDatastore)
			d.OnStatusUpdated(api.ResyncInProgress)
			onUpdates([]api.Update{KVUpdate("foo", "bar")})
			onUpdates([]api.Update{KVUpdate("foo2", "bar2")})
			d.OnStatusUpdated(api.InSync)

			applyNextBatchSync(d, rec)

			Expect(rec.FinalValues()).To(Equal(map[string]string{
				"foo":  "bar",
				"foo2": "bar2",
			}))
			Expect(rec.FinalSyncState()).To(Equal(api.InSync))
			Expect(rec.UpdatesSeen()).To(Equal([]string{
				// WaitForDatastore gets skipped since it's in the same batch.
				string(api.ResyncInProgress),
				"foo=bar",
				"foo2=bar2",
				string(api.InSync),
			}))

			// Now send in a deletion.
			rec.ResetUpdatesSeen()
			onUpdates([]api.Update{KVUpdate("foo", "")})
			applyNextBatchSync(d, rec)
			Expect(rec.FinalValues()).To(Equal(map[string]string{
				"foo2": "bar2",
			}))
			Expect(rec.FinalSyncState()).To(Equal(api.InSync))
			Expect(rec.UpdatesSeen()).To(Equal([]string{
				"foo=",
			}))

			// Now send in a deletion, which is reverted before being sent.
			rec.ResetUpdatesSeen()
			onUpdates([]api.Update{KVUpdate("foo2", "")})
			onUpdates([]api.Update{KVUpdate("foo2", "bar3")})
			applyNextBatchSync(d, rec)
			Expect(rec.FinalValues()).To(Equal(map[string]string{
				"foo2": "bar3",
			}))
			Expect(rec.FinalSyncState()).To(Equal(api.InSync))
			Expect(rec.UpdatesSeen()).To(Equal([]string{
				"foo2=bar3",
			}))

			// Update both keys, should work as normal.
			rec.ResetUpdatesSeen()
			onUpdates([]api.Update{KVUpdate("foo", "bar")})
			onUpdates([]api.Update{KVUpdate("foo2", "bar2")})
			applyNextBatchSync(d, rec)
			Expect(rec.FinalValues()).To(Equal(map[string]string{
				"foo":  "bar",
				"foo2": "bar2",
			}))
			Expect(rec.FinalSyncState()).To(Equal(api.InSync))
			Expect(rec.UpdatesSeen()).To(Equal([]string{
				// WaitForDatastore gets skipped since it's in the same batch.
				"foo=bar",
				"foo2=bar2",
			}))
		})
	}
}

func TestDedupeBuffer_SyncWithDupes(t *testing.T) {
	for _, onUpdatesVersion := range []string{"KeysKnown", "KeysNotKnown"} {
		t.Run(onUpdatesVersion, func(t *testing.T) {
			RegisterTestingT(t)
			d := New()
			onUpdates := wrapOnUpdates(d, onUpdatesVersion)
			rec := NewReceiver()

			d.OnStatusUpdated(api.WaitForDatastore)
			d.OnStatusUpdated(api.ResyncInProgress)
			onUpdates([]api.Update{KVUpdate("foo", "bar")})
			onUpdates([]api.Update{KVUpdate("foo2", "bar2")})
			onUpdates([]api.Update{KVUpdate("foo3", "bar3")})
			onUpdates([]api.Update{KVUpdate("foo", "bar3")})
			onUpdates([]api.Update{KVUpdate("foo2", "")})
			d.OnStatusUpdated(api.InSync)
			d.OnStatusUpdated(api.ResyncInProgress)
			d.OnStatusUpdated(api.ResyncInProgress)
			d.OnStatusUpdated(api.InSync)

			applyNextBatchSync(d, rec)

			Expect(rec.FinalValues()).To(Equal(map[string]string{
				"foo":  "bar3",
				"foo3": "bar3",
			}))
			Expect(rec.FinalSyncState()).To(Equal(api.InSync))
			Expect(rec.UpdatesSeen()).To(Equal([]string{
				// WaitForDatastore skipped.
				string(api.ResyncInProgress),
				"foo=bar3", // Update leap-frogs the original value.
				"foo3=bar3",
				string(api.InSync),
			}))
		})
	}
}

func applyNextBatchSync(d *DedupeBuffer, r *Receiver) {
	Expect(d.pendingUpdates.Len()).NotTo(BeZero(), "Nothing on queue, sendNextBatchToSink would block")
	d.sendNextBatchToSink(r)
}

func wrapOnUpdates(d *DedupeBuffer, onUpdatesVersion string) func(updates []api.Update) {
	onUpdates := d.OnUpdates
	if onUpdatesVersion == "KeysKnown" {
		onUpdates = func(updates []api.Update) {
			var keys []string
			for _, upd := range updates {
				key, err := model.KeyToDefaultPath(upd.Key)
				Expect(err).NotTo(HaveOccurred())
				keys = append(keys, key)
			}
			d.OnUpdatesKeysKnown(updates, keys)
		}
	}
	return onUpdates
}

func KVUpdate(key, value string) api.Update {
	u := api.Update{
		KVPair: model.KVPair{
			Key: model.HostConfigKey{
				Hostname: "foo",
				Name:     key,
			},
		},
	}
	if value != "" {
		u.KVPair.Value = value
	}
	return u
}

type Receiver struct {
	mutex sync.Mutex

	finalValues    map[string]string
	updatesSeen    []string
	finalSyncState api.SyncStatus
}

func (r *Receiver) FinalValues() map[string]string {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	fvCopy := map[string]string{}
	for k, v := range r.finalValues {
		fvCopy[k] = v
	}
	return fvCopy
}

func (r *Receiver) UpdatesSeen() []string {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	var usCopy []string
	for _, v := range r.updatesSeen {
		usCopy = append(usCopy, v)
	}
	return usCopy
}

func (r *Receiver) FinalSyncState() api.SyncStatus {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.finalSyncState
}

func (r *Receiver) OnStatusUpdated(status api.SyncStatus) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.updatesSeen = append(r.updatesSeen, string(status))
	r.finalSyncState = status
}

func (r *Receiver) OnUpdates(updates []api.Update) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	for _, update := range updates {
		k := update.Key.(model.HostConfigKey).Name
		var v string
		if update.Value == nil {
			delete(r.finalValues, k)
		} else {
			v = update.Value.(string)
			r.finalValues[k] = v
		}
		r.updatesSeen = append(r.updatesSeen, fmt.Sprintf("%s=%s", k, v))
	}
}

func (r *Receiver) ResetUpdatesSeen() {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.updatesSeen = nil
}

func NewReceiver() *Receiver {
	return &Receiver{
		finalValues: map[string]string{},
	}
}
