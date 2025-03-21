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
type localBGPPeerWatcher struct {
	client                   *client
	mutex                    sync.Mutex
	activeFileNameToEpStatus map[string]epstatus.WorkloadEndpointStatus
	fileWatcher              *epstatus.FileWatcher
}

func NewLocalBGPPeerWatcher(client *client, prefix string, pollIntervalSeconds int) (*localBGPPeerWatcher, error) {
	if pollIntervalSeconds == 0 {
		pollIntervalSeconds = defaultPollIntervalSeconds
	}

	dir := filepath.Join(prefix, epstatus.GetDirStatus())

	w := &localBGPPeerWatcher{
		client:                   client,
		activeFileNameToEpStatus: map[string]epstatus.WorkloadEndpointStatus{},
		fileWatcher:              epstatus.NewFileWatcher(dir, time.Duration(pollIntervalSeconds)*time.Second),
	}
	w.fileWatcher.SetCallbacks(epstatus.Callbacks{
		OnFileCreation: w.OnFileCreation,
		OnFileUpdate:   w.OnFileUpdate,
		OnFileDeletion: w.OnFileDeletion,
	})

	return w, nil
}

func (w *localBGPPeerWatcher) Start() {
	w.fileWatcher.Start()
}

func (w *localBGPPeerWatcher) Stop() {
	w.fileWatcher.Stop()
}

func (w *localBGPPeerWatcher) OnFileCreation(fileName string) {
	logCxt := log.WithField("file", fileName)

	logCxt.Debug("Workload endpoint status file created")
	epStatus, err := epstatus.GetWorkloadEndpointStatusFromFile(fileName)
	if err != nil {
		logCxt.WithError(err).Warn("Failed to read endpoint status from file, it may just be created.")
		return
	}
	w.updateEpStatus(fileName, epStatus)
	w.client.recheckPeerConfig()
}

func (w *localBGPPeerWatcher) OnFileUpdate(fileName string) {
	logCxt := log.WithField("file", fileName)

	logCxt.Debug("Workload endpoint status file updated")
	epStatus, err := epstatus.GetWorkloadEndpointStatusFromFile(fileName)
	if err != nil {
		logCxt.WithError(err).Error("Failed to read endpoint status from file")
		return
	}
	w.updateEpStatus(fileName, epStatus)
	w.client.recheckPeerConfig()
}

func (w *localBGPPeerWatcher) OnFileDeletion(fileName string) {
	log.WithField("file", fileName).Debug("Workload endpoint status file deleted")

	w.deleteEpStatus(fileName)
	w.client.recheckPeerConfig()
}

func (w *localBGPPeerWatcher) updateEpStatus(fileName string, epStatus *epstatus.WorkloadEndpointStatus) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.activeFileNameToEpStatus[fileName] = *epStatus
}

func (w *localBGPPeerWatcher) deleteEpStatus(fileName string) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	delete(w.activeFileNameToEpStatus, fileName)
}

type localBGPPeerData struct {
	name        string
	bgpPeerName string
	ipv4        string
	ipv6        string
}

func (w *localBGPPeerWatcher) GetActiveLocalBGPPeers() []localBGPPeerData {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	peerData := []localBGPPeerData{}

	for name, epStatus := range w.activeFileNameToEpStatus {
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
