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
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
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
		logCtx:    logrus.WithField("syncer", st),
		cache:     map[string]any{},
	}
}

type syncerCallbacks struct {
	Type      syncproto.SyncerType
	startTime time.Time
	logCtx    *logrus.Entry

	lock           sync.Mutex
	numUpdatesSeen int
	cache          map[string]any
	status         api.SyncStatus
}

func (s *syncerCallbacks) OnStatusUpdated(status api.SyncStatus) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.logCtx.WithFields(logrus.Fields{
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
			logrus.WithError(err).Panic("Failed to serialise key")
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

	s.logCtx.WithFields(logrus.Fields{
		"status":       s.status,
		"numKnownKVs":  len(s.cache),
		"totalUpdates": s.numUpdatesSeen,
	}).Info("Syncer stats")
}

const (
	typhaNamespace      = "calico-system"
	typhaK8sServiceName = "calico-typha"
	typhaCAFile         = "/etc/pki/tls/certs/ca.crt"
	typhaCertFile       = "/node-certs/tls.crt"
	typhaKeyFile        = "/node-certs/tls.key"
	typhaCN             = "typha-server"
	typhaURISAN         = ""
)

func main() {
	defer func() {
		logrus.WithField(logutils.FieldForceFlush, true).Warning("Exiting...")
	}()
	configureLogging()
	logrus.WithFields(logrus.Fields{
		"version": buildinfo.Version,
	}).Info("Mock Calico Node starting up")

	hostname, err := names.Hostname()
	if err != nil {
		logrus.WithError(err).Panic("Failed to get hostname")
	}

	for _, st := range syncproto.AllSyncerTypes {
		startTyphaClient(st, hostname)
	}
	logrus.Info("Started all clients.")
	var cpuTimeUsed time.Duration
	interval := 10 * time.Second
	for {
		time.Sleep(interval)
		newTimeUsed := getMyCPUTime()
		percent := float64(newTimeUsed-cpuTimeUsed) / float64(interval)
		logrus.Infof("My CPU usage: %.2f%%", percent*100)
		cpuTimeUsed = newTimeUsed
	}
}

func startTyphaClient(st syncproto.SyncerType, hostname string) {
	logrus.Infof("Starting sycher of type: %v", st)
	cbs := newSyncerCallbacks(st)
	typhaDiscoverer := discovery.New(
		discovery.WithInClusterKubeClient(),
		discovery.WithKubeService(typhaNamespace, typhaK8sServiceName),
	)
	_, err := typhaDiscoverer.LoadTyphaAddrs()
	if err != nil {
		logrus.WithError(err).Panic("Failed to discover Typha.")
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
		logrus.WithError(err).Panic("Failed to start typha client.")
	}
	done := make(chan struct{})
	go func(st syncproto.SyncerType) {
		defer close(done)
		client.Finished.Wait()
		logrus.WithField("syncer", st).Warning("Disconnected from Typha. (Will reconnect.)")
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
		logrus.WithError(err).Panic("Failed to read scheduler stats")
	}
	usedNanosStr := strings.SplitN(string(rawStats), " ", 2)[0]
	usedNanosInt, err := strconv.ParseUint(usedNanosStr, 10, 64)
	if err != nil {
		logrus.WithError(err).Panic("Failed to read scheduler stats")
	}
	return time.Duration(usedNanosInt)
}

func configureLogging() {
	logLevel := logrus.InfoLevel
	logrus.SetLevel(logLevel)
	logutils.ConfigureFormatter("mocknode")

	// Disable logrus' default output, which only supports a single destination.  We use the
	// hook above to fan out logs to multiple destinations.
	logrus.SetOutput(&logutils.NullWriter{})

	// Since we push our logs onto a second thread via a channel, we can disable the
	// Logger's built-in mutex completely.
	logrus.StandardLogger().SetNoLock()
	screenDest := logutils.NewStreamDestination(
		logLevel,
		os.Stdout,
		make(chan logutils.QueuedLog, 1000),
		false,
		counterLogErrors,
	)
	hook := logutils.NewBackgroundHook(
		logutils.FilterLevels(logLevel),
		logrus.PanicLevel,
		[]*logutils.Destination{screenDest},
		counterLogErrors,
	)
	hook.Start()
	logrus.AddHook(hook)
}
