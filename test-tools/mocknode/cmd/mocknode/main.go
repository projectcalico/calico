// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
	"context"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/projectcalico/calico/lib/std/log"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	"github.com/projectcalico/calico/pkg/buildinfo"
	"github.com/projectcalico/calico/typha/pkg/discovery"
	"github.com/projectcalico/calico/typha/pkg/syncclient"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
)

var counterLogErrors = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "mocknode_log_errors",
	Help: "Number of errors encountered while logging.",
})

func init() {
	prometheus.MustRegister(
		counterLogErrors,
	)
}

func newSyncerCallbacks(st syncproto.SyncerType) *syncerCallbacks {
	return &syncerCallbacks{
		Type:      st,
		startTime: time.Now(),
		logCtx:    log.WithField("syncer", st),
		cache:     map[string]any{},
	}
}

type syncerCallbacks struct {
	Type      syncproto.SyncerType
	startTime time.Time
	logCtx    log.Entry

	lock           sync.Mutex
	numUpdatesSeen int
	cache          map[string]any
	status         api.SyncStatus
}

func (s *syncerCallbacks) OnStatusUpdated(status api.SyncStatus) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.logCtx.WithFields(log.Fields{
		"status":         status,
		"numKnownKVs":    len(s.cache),
		"timeSinceStart": time.Since(s.startTime),
	}).Info("Status update from Typha")
	s.status = status
}

func (s *syncerCallbacks) OnUpdates(updates []api.Update) {
	s.lock.Lock()
	defer s.lock.Unlock()

	for _, u := range updates {
		s.numUpdatesSeen++
		path, err := model.KeyToDefaultPath(u.Key)
		if err != nil {
			log.WithError(err).Panic("Failed to serialise key")
		}
		if u.KVPair.Value == nil {
			delete(s.cache, path)
		} else {
			s.cache[path] = u.Value
		}
	}
}

func (s *syncerCallbacks) LogStats() {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.logCtx.WithFields(log.Fields{
		"status":       s.status,
		"numKnownKVs":  len(s.cache),
		"totalUpdates": s.numUpdatesSeen,
	}).Info("Syncer stats")
}

const (
	typhaNamespace      = "calico-system"
	typhaK8sServiceName = "calico-typha"
	typhaCAFile         = "/etc/pki/tls/certs/tigera-ca-bundle.crt"
	typhaCertFile       = "/node-certs/tls.crt"
	typhaKeyFile        = "/node-certs/tls.key"
	typhaCN             = "typha-server"
	typhaURISAN         = ""
)

func main() {
	defer func() {
		log.WithField(log.FieldForceFlush, true).Warning("Exiting...")
	}()
	configureLogging()
	log.WithFields(log.Fields{
		"version": buildinfo.Version,
	}).Info("Mock Calico Node starting up")

	hostname, err := names.Hostname()
	if err != nil {
		log.WithError(err).Panic("Failed to get hostname")
	}

	for _, st := range syncproto.AllSyncerTypes {
		startTyphaClient(st, hostname)
	}
	log.Info("Started all clients.")
	var cpuTimeUsed time.Duration
	interval := 10 * time.Second
	for {
		time.Sleep(interval)
		newTimeUsed := getMyCPUTime()
		percent := float64(newTimeUsed-cpuTimeUsed) / float64(interval)
		log.Infof("My CPU usage: %.2f%%", percent*100)
		cpuTimeUsed = newTimeUsed
	}
}

func startTyphaClient(st syncproto.SyncerType, hostname string) {
	log.Infof("Starting sycher of type: %v", st)
	cbs := newSyncerCallbacks(st)
	typhaDiscoverer := discovery.New(
		discovery.WithInClusterKubeClient(),
		discovery.WithKubeService(typhaNamespace, typhaK8sServiceName),
	)
	_, err := typhaDiscoverer.LoadTyphaAddrs()
	if err != nil {
		log.WithError(err).Panic("Failed to discover Typha.")
	}
	client := syncclient.New(typhaDiscoverer,
		buildinfo.Version,
		hostname,
		"",
		cbs,
		&syncclient.Options{
			KeyFile:               typhaKeyFile,
			CertFile:              typhaCertFile,
			CAFile:                typhaCAFile,
			ServerCN:              typhaCN,
			ServerURISAN:          typhaURISAN,
			SyncerType:            st,
			DebugDiscardKVUpdates: false,
		})
	err = client.Start(context.Background())
	if err != nil {
		log.WithError(err).Panic("Failed to start typha client.")
	}
	done := make(chan struct{})
	go func(st syncproto.SyncerType) {
		defer close(done)
		client.Finished.Wait()
		log.WithField("syncer", st).Warning("Disconnected from Typha. (Will reconnect.)")
		time.Sleep(2 * time.Second)
		go startTyphaClient(st, hostname)
	}(st)
	go func() {
		for {
			select {
			case <-time.After(10 * time.Second):
				cbs.LogStats()
			case <-done:
				return
			}
		}
	}()
}

func getMyCPUTime() time.Duration {
	rawStats, err := os.ReadFile("/proc/self/schedstat")
	if err != nil {
		log.WithError(err).Panic("Failed to read scheduler stats")
	}
	usedNanosStr := strings.SplitN(string(rawStats), " ", 2)[0]
	usedNanosInt, err := strconv.ParseUint(usedNanosStr, 10, 64)
	if err != nil {
		log.WithError(err).Panic("Failed to read scheduler stats")
	}
	return time.Duration(usedNanosInt)
}

func configureLogging() {
	logLevel := log.InfoLevel
	log.SetLevel(logLevel)
	log.ConfigureFormatter("mocknode")

	// Disable logrus' default output, which only supports a single destination.  We use the
	// hook above to fan out logs to multiple destinations.
	log.SetOutput(&log.NullWriter{})

	// Since we push our logs onto a second thread via a channel, we can disable the
	// Logger's built-in mutex completely.
	log.StandardLogger().SetNoLock()
	screenDest := log.NewStreamDestination(
		logLevel,
		os.Stdout,
		make(chan log.QueuedLog, 1000),
		false,
		counterLogErrors,
	)
	hook := log.NewBackgroundHook(
		log.FilterLevels(logLevel),
		log.PanicLevel,
		[]*log.Destination{screenDest},
		counterLogErrors,
	)
	hook.Start()
	log.AddHook(hook)
}
