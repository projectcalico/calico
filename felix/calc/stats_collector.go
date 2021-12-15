// Copyright (c) 2016-2018 Tigera, Inc. All rights reserved.

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

package calc

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

var (
	gaugeClusNumHosts = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_cluster_num_hosts",
		Help: "Total number of calico hosts in the cluster.",
	})
	gaugeClusNumHostEndpoints = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_cluster_num_host_endpoints",
		Help: "Total number of host endpoints cluster-wide.",
	})
	gaugeClusNumWorkloadEndpoints = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_cluster_num_workload_endpoints",
		Help: "Total number of workload endpoints cluster-wide.",
	})
	gaugeClusNumPolicies = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_cluster_num_policies",
		Help: "Total number of policies cluster-wide.",
	})
	gaugeClusNumProfiles = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_cluster_num_profiles",
		Help: "Total number of profiles cluster-wide.",
	})
)

func init() {
	prometheus.MustRegister(gaugeClusNumHosts)
	prometheus.MustRegister(gaugeClusNumHostEndpoints)
	prometheus.MustRegister(gaugeClusNumWorkloadEndpoints)
	prometheus.MustRegister(gaugeClusNumPolicies)
	prometheus.MustRegister(gaugeClusNumProfiles)
}

type StatsCollector struct {
	keyCountByHost       map[string]int
	numWorkloadEndpoints int
	numHostEndpoints     int
	numPolicies          int
	numProfiles          int
	numALPPolicies       int

	lastUpdate StatsUpdate
	inSync     bool

	Callback func(StatsUpdate) error
}

type StatsUpdate struct {
	NumHosts             int
	NumWorkloadEndpoints int
	NumHostEndpoints     int
	NumPolicies          int
	NumProfiles          int
	NumALPPolicies       int
}

func (s StatsUpdate) String() string {
	return fmt.Sprintf("%#v", s)
}

func NewStatsCollector(callback func(StatsUpdate) error) *StatsCollector {
	return &StatsCollector{
		keyCountByHost: make(map[string]int),
		lastUpdate:     StatsUpdate{NumHosts: -1},
		Callback:       callback,
	}
}

func (s *StatsCollector) RegisterWith(calcGraph *CalcGraph) {
	calcGraph.AllUpdDispatcher.Register(model.HostIPKey{}, s.OnUpdate)
	calcGraph.AllUpdDispatcher.Register(model.WorkloadEndpointKey{}, s.OnUpdate)
	calcGraph.AllUpdDispatcher.Register(model.HostEndpointKey{}, s.OnUpdate)
	calcGraph.AllUpdDispatcher.Register(model.HostConfigKey{}, s.OnUpdate)
	calcGraph.AllUpdDispatcher.RegisterStatusHandler(s.OnStatusUpdate)
	calcGraph.activeRulesCalculator.OnPolicyCountsChanged = s.UpdatePolicyCounts
}

func (s *StatsCollector) OnStatusUpdate(status api.SyncStatus) {
	log.WithField("status", status).Debug("Datastore status updated")
	if status == api.InSync {
		s.inSync = true
		s.sendUpdate()
	}
}

func (s *StatsCollector) OnUpdate(update api.Update) (filterOut bool) {
	hostname := ""
	var counter *int
	switch key := update.Key.(type) {
	case model.HostIPKey:
		hostname = key.Hostname
	case model.WorkloadEndpointKey:
		hostname = key.Hostname
		counter = &s.numWorkloadEndpoints
	case model.HostEndpointKey:
		hostname = key.Hostname
		counter = &s.numHostEndpoints
	case model.HostConfigKey:
		hostname = key.Hostname
	}
	if hostname == "" {
		log.WithField("key", update.Key).Warn("Failed to get hostname")
		return
	}
	if update.UpdateType == api.UpdateTypeKVNew {
		s.keyCountByHost[hostname] += 1
		log.WithFields(log.Fields{
			"key":      update.Key,
			"host":     hostname,
			"newCount": s.keyCountByHost[hostname],
		}).Debug("Host-specific key added")
		if counter != nil {
			*counter += 1
		}
	} else if update.UpdateType == api.UpdateTypeKVDeleted {
		s.keyCountByHost[hostname] -= 1
		log.WithFields(log.Fields{
			"key":      update.Key,
			"host":     hostname,
			"newCount": s.keyCountByHost[hostname],
		}).Debug("Host-specific key deleted")
		if s.keyCountByHost[hostname] <= 0 {
			log.WithField("host", hostname).Debug("Host no longer has any keys")
			delete(s.keyCountByHost, hostname)
		}
		if counter != nil {
			*counter -= 1
		}
	}
	s.sendUpdate()
	return
}

func (s *StatsCollector) UpdatePolicyCounts(numPolicies, numProfiles, numALPPolicies int) {
	if numPolicies == s.numPolicies && numProfiles == s.numProfiles && numALPPolicies == s.numALPPolicies {
		return
	}

	log.WithFields(log.Fields{
		"numPolicies":    numPolicies,
		"numProfiles":    numProfiles,
		"numALPPolicies": numALPPolicies,
	}).Debug("Number of policies/profiles changed")
	s.numPolicies = numPolicies
	s.numProfiles = numProfiles
	s.numALPPolicies = numALPPolicies
	s.sendUpdate()
}

func (s *StatsCollector) sendUpdate() {
	log.Debug("Checking whether we should send an update")
	update := StatsUpdate{
		NumHosts:             len(s.keyCountByHost),
		NumHostEndpoints:     s.numHostEndpoints,
		NumWorkloadEndpoints: s.numWorkloadEndpoints,
		NumPolicies:          s.numPolicies,
		NumProfiles:          s.numProfiles,
		NumALPPolicies:       s.numALPPolicies,
	}
	gaugeClusNumHosts.Set(float64(len(s.keyCountByHost)))
	gaugeClusNumWorkloadEndpoints.Set(float64(s.numWorkloadEndpoints))
	gaugeClusNumHostEndpoints.Set(float64(s.numHostEndpoints))
	gaugeClusNumPolicies.Set(float64(s.numPolicies))
	gaugeClusNumProfiles.Set(float64(s.numProfiles))
	if s.inSync && s.lastUpdate != update {
		if err := s.Callback(update); err != nil {
			log.WithError(err).Warn("Failed to report stats")
		} else {
			log.WithField("stats", update).Debug("Sent stats update")
			s.lastUpdate = update
		}
	}
}
