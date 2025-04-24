// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package calico

import (
	"net"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	epstatus "github.com/projectcalico/calico/libcalico-go/lib/epstatusfile"
)

const (
	defaultPollIntervalSeconds = 30
)

// LocalBGPPeerWatcher watches endpoint status files and maintain
// a cache to store active workload endpoint status.
type LocalBGPPeerWatcher struct {
	client                               *client
	mutex                                sync.Mutex
	activeLocalBGPPeerFileNameToEpStatus map[string]epstatus.WorkloadEndpointStatus
	fileWatcher                          *epstatus.FileWatcher
}

func NewLocalBGPPeerWatcher(client *client, prefix string, pollIntervalSeconds int) (*LocalBGPPeerWatcher, error) {
	if pollIntervalSeconds == 0 {
		pollIntervalSeconds = defaultPollIntervalSeconds
	}

	dir := filepath.Join(prefix, epstatus.GetDirStatus())

	w := &LocalBGPPeerWatcher{
		client:                               client,
		activeLocalBGPPeerFileNameToEpStatus: map[string]epstatus.WorkloadEndpointStatus{},
		fileWatcher:                          epstatus.NewFileWatcher(dir, time.Duration(pollIntervalSeconds)*time.Second),
	}
	w.fileWatcher.SetCallbacks(epstatus.Callbacks{
		OnFileCreation: w.OnFileCreation,
		OnFileUpdate:   w.OnFileUpdate,
		OnFileDeletion: w.OnFileDeletion,
		OnInSync:       w.OnInSync,
	})

	return w, nil
}

func (w *LocalBGPPeerWatcher) Start() {
	w.fileWatcher.Start()
}

func (w *LocalBGPPeerWatcher) Stop() {
	w.fileWatcher.Stop()
}

func (w *LocalBGPPeerWatcher) OnFileCreation(fileName string) {
	logCxt := log.WithField("file", fileName)

	logCxt.Debug("Workload endpoint status file created")
	epStatus, err := epstatus.GetWorkloadEndpointStatusFromFile(fileName)
	if err != nil {
		logCxt.WithError(err).Warn("Failed to read endpoint status from file, it may just be created.")
		return
	}
	if w.updateEpStatus(fileName, epStatus) {
		w.client.recheckPeerConfig("endpoint status file created")
	}
}

func (w *LocalBGPPeerWatcher) OnFileUpdate(fileName string) {
	logCxt := log.WithField("file", fileName)

	logCxt.Debug("Workload endpoint status file updated")
	epStatus, err := epstatus.GetWorkloadEndpointStatusFromFile(fileName)
	if err != nil {
		// Avoid spurious error messages when the file is mid-update.
		time.Sleep(50 * time.Millisecond)
		epStatus, err = epstatus.GetWorkloadEndpointStatusFromFile(fileName)
		if err != nil {
			logCxt.WithError(err).Error("Failed to read endpoint status from file")
			return
		}
	}
	if w.updateEpStatus(fileName, epStatus) {
		w.client.recheckPeerConfig("endpoint status file updated")
	}
}

func (w *LocalBGPPeerWatcher) OnFileDeletion(fileName string) {
	log.WithField("file", fileName).Debug("Workload endpoint status file deleted")

	if w.deleteEpStatus(fileName) {
		w.client.recheckPeerConfig("endpoint status file deleted")
	}
}

func (w *LocalBGPPeerWatcher) OnInSync(inSync bool) {
	log.WithField("newValue", inSync).Debug("Received new inSync msg from upstream")

	w.client.OnSyncChange(SourceLocalBGPPeerWatcher, inSync)
}

func (w *LocalBGPPeerWatcher) updateEpStatus(fileName string, epStatus *epstatus.WorkloadEndpointStatus) (changed bool) {
	if epStatus.BGPPeerName == "" {
		return w.deleteEpStatus(fileName)
	}

	w.mutex.Lock()
	defer w.mutex.Unlock()
	old, ok := w.activeLocalBGPPeerFileNameToEpStatus[fileName]
	if ok && reflect.DeepEqual(old, *epStatus) {
		log.WithField("file", fileName).Debug("Workload endpoint status file unchanged")
		return false
	}
	w.activeLocalBGPPeerFileNameToEpStatus[fileName] = *epStatus
	return true
}

func (w *LocalBGPPeerWatcher) deleteEpStatus(fileName string) (changed bool) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	if _, ok := w.activeLocalBGPPeerFileNameToEpStatus[fileName]; !ok {
		log.WithField("file", fileName).Debug("Endpoint status already gone.")
		return false
	}
	delete(w.activeLocalBGPPeerFileNameToEpStatus, fileName)
	return true
}

type localBGPPeerData struct {
	name        string
	bgpPeerName string
	ipv4        string
	ipv6        string
}

func (w *LocalBGPPeerWatcher) GetActiveLocalBGPPeers() []localBGPPeerData {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	var peerData []localBGPPeerData

	for name, epStatus := range w.activeLocalBGPPeerFileNameToEpStatus {
		var ipv4, ipv6 string
		if len(epStatus.Ipv4Nets) != 0 {
			ip, _, err := net.ParseCIDR(epStatus.Ipv4Nets[0])
			if err != nil {
				log.WithError(err).Warn("Workload endpoint status does not have a valid Ipv4Nets, ignore it for now")
				continue
			}
			ipv4 = ip.String()
		}
		if len(epStatus.Ipv6Nets) != 0 {
			ip, _, err := net.ParseCIDR(epStatus.Ipv6Nets[0])
			if err != nil {
				log.WithError(err).Warn("Workload endpoint status does not have a valid Ipv6Nets, ignore it for now")
				continue
			}
			ipv6 = ip.String()
		}

		if ipv4 == "" && ipv6 == "" {
			log.WithField("name", name).Warn("Workload endpoint status does not have a valid ip yet, ignore it for now")
			continue
		}

		peerData = append(peerData, localBGPPeerData{
			name:        name,
			bgpPeerName: epStatus.BGPPeerName,
			ipv4:        ipv4,
			ipv6:        ipv6,
		})
	}

	return peerData
}
