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

package usagerep

import (
	"github.com/projectcalico/felix/go/felix/jitter"

	"encoding/json"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/felix/go/felix/buildinfo"
	"math/rand"
	"net/http"
	"net/url"
	"time"
)

const (
	baseURL = "https://usage.projectcalico.org/UsageCheck/calicoVersionCheck?"
)

func PeriodicallyReportUsage(interval time.Duration, hostname, clusterGUID, clusterType string, numHostsC <-chan int) {
	log.Info("Usage reporting thread started, waiitng for size estimate")
	estimatedClusterSize := <-numHostsC
	log.WithField("size", estimatedClusterSize).Info("Initial cluster size read")
	if estimatedClusterSize > 25 {
		// Avoid thundering herd by adding jitter to startup for a large
		// cluster.
		preJitter := time.Duration(rand.Intn(estimatedClusterSize)) * time.Second
		log.WithField("delay", preJitter).Info("Waiting before first check-in")
		time.Sleep(preJitter)
	}
	ReportUsage(hostname, clusterGUID, clusterType, estimatedClusterSize)
	ticker := jitter.NewTicker(interval, interval/10)
	for {
		select {
		case estimatedClusterSize = <-numHostsC:
		case <-ticker.C:
			ReportUsage(hostname, clusterGUID, clusterType, estimatedClusterSize)
		}
	}
}

func ReportUsage(hostname, clusterGUID, clusterType string, estimatedClusterSize int) {
	if clusterType == "" {
		clusterType = "unknown"
	}
	if clusterGUID == "" {
		clusterType = "baddecaf"
	}
	log.WithFields(log.Fields{
		"hostname":             hostname,
		"clusterGUID":          clusterGUID,
		"clusterType":          clusterType,
		"estimatedClusterSize": estimatedClusterSize,
		"version":              buildinfo.Version,
		"gitRevision":          buildinfo.GitRevision,
	}).Info("Reporting cluster usage/checking for deprecation warnings.")
	queryParams := url.Values{
		"hostname":     {hostname},
		"guid":         {clusterGUID},
		"cluster_type": {clusterType},
		"size":         {fmt.Sprintf("%v", estimatedClusterSize)},
		"version":      {buildinfo.Version},
		"git_revision": {buildinfo.GitRevision},
		"felix_type":   {"go"},
	}
	fullURL := baseURL + queryParams.Encode()
	log.WithField("url", fullURL).Debug("Calculated URL.")
	resp, err := http.Get(fullURL)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		log.WithError(err).Info("Failed to report usage/get deprecation warnings.")
		return
	}
	jsonResp := map[string]interface{}{}
	if err := json.NewDecoder(resp.Body).Decode(&jsonResp); err != nil {
		log.WithError(err).Warn(
			"Failed to decode report server response")
		return
	} else {
		log.WithField("json", jsonResp).Debug("Response")
	}
	if warn, ok := jsonResp["usage_warning"]; ok {
		log.Warnf("Usage warning: %v", warn)
	}
}
