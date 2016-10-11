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

package etcd

import (
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/coreos/etcd/client"
	etcd "github.com/coreos/etcd/client"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/hwm"
	"golang.org/x/net/context"
)

func newSyncer(keysAPI etcd.KeysAPI, callbacks api.SyncerCallbacks) *etcdSyncer {
	return &etcdSyncer{
		keysAPI:   keysAPI,
		callbacks: callbacks,
	}
}

type etcdSyncer struct {
	callbacks api.SyncerCallbacks
	keysAPI   etcd.KeysAPI
	OneShot   bool
}

func (syn *etcdSyncer) Start() {
	// Start a background thread to read events from etcd.  It will
	// queue events onto the etcdEvents channel.  If it drops out of sync,
	// it will signal on the resyncIndex channel.
	log.Info("Starting etcd Syncer")
	etcdEvents := make(chan event, 20000)
	triggerResync := make(chan uint64, 5)
	initialSnapshotIndex := make(chan uint64)
	if !syn.OneShot {
		log.Info("Syncer not in one-shot mode, starting watcher thread")
		go syn.watchEtcd(etcdEvents, triggerResync, initialSnapshotIndex)
	}

	// Start a background thread to read snapshots from etcd.  It will
	// read a start-of-day snapshot and then wait to be signalled on the
	// resyncIndex channel.
	snapshotUpdates := make(chan event)
	go syn.readSnapshotsFromEtcd(snapshotUpdates, triggerResync, initialSnapshotIndex)
	go syn.mergeUpdates(snapshotUpdates, etcdEvents)
}

const (
	actionSet uint8 = iota
	actionDel
	actionSnapFinished
)

// TODO Split this into different types of struct and use a type-switch to unpack.
type event struct {
	action           uint8
	modifiedIndex    uint64
	snapshotIndex    uint64
	key              string
	value            string
	snapshotStarting bool
	snapshotFinished bool
}

func (syn *etcdSyncer) readSnapshotsFromEtcd(snapshotUpdates chan<- event, triggerResync <-chan uint64, initialSnapshotIndex chan<- uint64) {
	log.Info("Syncer snapshot-reading thread started")
	getOpts := client.GetOptions{
		Recursive: true,
		Sort:      false,
		Quorum:    false,
	}
	var highestSnapshotIndex uint64
	var minIndex uint64

	for {
		if highestSnapshotIndex > 0 {
			// Wait for the watcher thread to tell us what index
			// it starts from.  We need to load a snapshot with
			// an equal or later index, otherwise we could miss
			// some updates.  (Since we may connect to a follower
			// server, it's possible, if unlikely, for us to read
			// a stale snapshot.)
			minIndex = <-triggerResync
			log.Infof("Asked for snapshot > %v; last snapshot was %v",
				minIndex, highestSnapshotIndex)
			if highestSnapshotIndex >= minIndex {
				// We've already read a newer snapshot, no
				// need to re-read.
				log.Info("Snapshot already new enough")
				continue
			}
		}

	readRetryLoop:
		for {
			resp, err := syn.keysAPI.Get(context.Background(),
				"/calico/v1", &getOpts)
			if err != nil {
				if syn.OneShot {
					// One-shot mode is used to grab a snapshot and then
					// stop.  We don't want to go into a retry loop.
					log.Fatal("Failed to read snapshot from etcd: ", err)
				}
				log.Warning("Error getting snapshot, retrying...", err)
				time.Sleep(1 * time.Second)
				continue readRetryLoop
			}

			if resp.Index < minIndex {
				log.Info("Retrieved stale snapshot, rereading...")
				continue readRetryLoop
			}

			// If we get here, we should have a good
			// snapshot.  Send it to the merge thread.
			sendNode(resp.Node, snapshotUpdates, resp)
			snapshotUpdates <- event{
				action:        actionSnapFinished,
				snapshotIndex: resp.Index,
			}
			if resp.Index > highestSnapshotIndex {
				if highestSnapshotIndex == 0 {
					initialSnapshotIndex <- resp.Index
					close(initialSnapshotIndex)
				}
				highestSnapshotIndex = resp.Index
			}
			break readRetryLoop
		}
	}
}

func sendNode(node *client.Node, snapshotUpdates chan<- event, resp *client.Response) {
	if !node.Dir {
		snapshotUpdates <- event{
			key:           node.Key,
			modifiedIndex: node.ModifiedIndex,
			snapshotIndex: resp.Index,
			value:         node.Value,
			action:        actionSet,
		}
	} else {
		for _, child := range node.Nodes {
			sendNode(child, snapshotUpdates, resp)
		}
	}
}

func (syn *etcdSyncer) watchEtcd(etcdEvents chan<- event, triggerResync chan<- uint64, initialSnapshotIndex <-chan uint64) {
	log.Info("Watcher started, waiting for initial snapshot index...")
	startIndex := <-initialSnapshotIndex
	log.WithField("index", startIndex).Info("Received initial snapshot index")

	watcherOpts := client.WatcherOptions{
		AfterIndex: startIndex,
		Recursive:  true,
	}
	watcher := syn.keysAPI.Watcher("/calico/v1", &watcherOpts)
	inSync := true
	for {
		resp, err := watcher.Next(context.Background())
		if err != nil {
			switch err := err.(type) {
			case client.Error:
				errCode := err.Code
				if errCode == client.ErrorCodeWatcherCleared ||
					errCode == client.ErrorCodeEventIndexCleared {
					log.Warning("Lost sync with etcd, restarting watcher")
					watcherOpts.AfterIndex = 0
					watcher = syn.keysAPI.Watcher("/calico/v1",
						&watcherOpts)
					inSync = false
					// FIXME, we'll only trigger a resync after the next event
					continue
				} else {
					log.Error("Error from etcd", err)
					time.Sleep(1 * time.Second)
				}
			case *client.ClusterError:
				log.Error("Cluster error from etcd", err)
				time.Sleep(1 * time.Second)
			default:
				panic(err)
			}
		} else {
			var actionType uint8
			switch resp.Action {
			case "set", "compareAndSwap", "update", "create":
				actionType = actionSet
			case "delete", "compareAndDelete", "expire":
				actionType = actionDel
			default:
				panic("Unknown action type")
			}

			node := resp.Node
			if node.Dir && actionType == actionSet {
				// Creation of a directory, we don't care.
				continue
			}
			if !inSync {
				// Tell the snapshot thread that we need a
				// new snapshot.  The snapshot needs to be
				// from our index or one lower.
				snapIdx := node.ModifiedIndex - 1
				log.Infof("Asking for snapshot @ %v",
					snapIdx)
				triggerResync <- snapIdx
				inSync = true
			}
			etcdEvents <- event{
				action:           actionType,
				modifiedIndex:    node.ModifiedIndex,
				key:              resp.Node.Key,
				value:            node.Value,
				snapshotStarting: !inSync,
			}
		}
	}
}

func (syn *etcdSyncer) mergeUpdates(snapshotUpdates <-chan event, watcherUpdates <-chan event) {
	var e event
	var minSnapshotIndex uint64
	hwms := hwm.NewHighWatermarkTracker()

	syn.callbacks.OnStatusUpdated(api.WaitForDatastore)
	for {
		select {
		case e = <-snapshotUpdates:
			log.Debugf("Snapshot update %v @ %v (snapshot @ %v)", e.key, e.modifiedIndex, e.snapshotIndex)
		case e = <-watcherUpdates:
			log.Debugf("Watcher update %v @ %v", e.key, e.modifiedIndex)
		}
		if e.snapshotStarting {
			// Watcher lost sync, need to track deletions until
			// we get a snapshot from after this index.
			log.Infof("Watcher out-of-sync, starting to track deletions")
			minSnapshotIndex = e.modifiedIndex
			syn.callbacks.OnStatusUpdated(api.ResyncInProgress)
		}
		switch e.action {
		case actionSet:
			var indexToStore uint64
			if e.snapshotIndex != 0 {
				// Store the snapshot index in the trie so that
				// we can scan the trie later looking for
				// prefixes that are older than the snapshot
				// (and hence must have been deleted while
				// we were out-of-sync).
				indexToStore = e.snapshotIndex
			} else {
				indexToStore = e.modifiedIndex
			}
			oldIdx := hwms.StoreUpdate(e.key, indexToStore)
			//log.Infof("%v update %v -> %v",
			//	e.key, oldIdx, e.modifiedIndex)
			if oldIdx < e.modifiedIndex {
				// Event is newer than value for that key.
				// Send the update to Felix.
				syn.sendUpdate(e.key, &e.value, e.modifiedIndex)
			}
		case actionDel:
			deletedKeys := hwms.StoreDeletion(e.key,
				e.modifiedIndex)
			log.Debugf("Prefix %v deleted; %v keys",
				e.key, len(deletedKeys))
			syn.sendDeletions(deletedKeys, e.modifiedIndex)
		case actionSnapFinished:
			if e.snapshotIndex >= minSnapshotIndex {
				// Now in sync.
				hwms.StopTrackingDeletions()
				deletedKeys := hwms.DeleteOldKeys(e.snapshotIndex)
				log.Infof("Snapshot finished at index %v; "+
					"%v keys deleted in cleanup.",
					e.snapshotIndex, len(deletedKeys))
				syn.sendDeletions(deletedKeys, e.snapshotIndex)
			}
			syn.callbacks.OnStatusUpdated(api.InSync)
		}
	}
}

func (syn *etcdSyncer) sendUpdate(key string, value *string, revision uint64) {
	log.Debugf("Parsing etcd key %#v", key)
	parsedKey := model.KeyFromDefaultPath(key)
	if parsedKey == nil {
		log.Debugf("Failed to parse key %v", key)
		if cb, ok := syn.callbacks.(api.SyncerParseFailCallbacks); ok {
			cb.ParseFailed(key, value)
		}
		return
	}
	log.Debugf("Parsed etcd key: %v", parsedKey)

	var parsedValue interface{}
	var err error
	if value != nil {
		parsedValue, err = model.ParseValue(parsedKey, []byte(*value))
		if err != nil {
			log.Warningf("Failed to parse value for %v: %#v", key, *value)
		}
		log.Debugf("Parsed value: %#v", parsedValue)
	}
	updates := []model.KVPair{
		{Key: parsedKey, Value: parsedValue, Revision: revision},
	}
	syn.callbacks.OnUpdates(updates)
}

func (syn *etcdSyncer) sendDeletions(deletedKeys []string, revision uint64) {
	updates := make([]model.KVPair, 0, len(deletedKeys))
	for _, key := range deletedKeys {
		parsedKey := model.KeyFromDefaultPath(key)
		if parsedKey == nil {
			log.Debugf("Failed to parse key %v", key)
			if cb, ok := syn.callbacks.(api.SyncerParseFailCallbacks); ok {
				cb.ParseFailed(key, nil)
			}
			continue
		}
		updates = append(updates, model.KVPair{
			Key:      parsedKey,
			Value:    nil,
			Revision: revision,
		})
	}
	syn.callbacks.OnUpdates(updates)
}
