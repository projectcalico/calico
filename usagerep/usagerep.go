// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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
	"github.com/projectcalico/felix/jitter"

	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/buildinfo"
	"github.com/projectcalico/felix/calc"
)

const (
	baseURL = "https://usage.projectcalico.org/UsageCheck/calicoVersionCheck?"
)

func PeriodicallyReportUsage(
	interval time.Duration,
	statsUpdateC <-chan calc.StatsUpdate,
	configUpdateC <-chan map[string]string,
) {
	var stats calc.StatsUpdate
	var config map[string]string
	var receivedFirstStats bool
	var tickerC <-chan time.Time
	initialDelayStarted := false
	initialDelayDone := make(chan struct{})

	maybeStartInitialDelay := func() {
		if !receivedFirstStats {
			return
		}
		if config == nil {
			return
		}
		if initialDelayStarted {
			return
		}

		// To avoid thundering herd, inject some startup jitter.
		initialDelay := calculateInitialDelay(stats.NumHosts)
		func() {
			log.WithField("delay", initialDelay).Info("Waiting before first check-in")
			time.Sleep(initialDelay)
			close(initialDelayDone)
		}()
		initialDelayStarted = true
	}

	doReport := func() {
		ReportUsage(config["ClusterGUID"], config["ClusterType"], config["CalicoVersion"], stats)
	}

	for {
		select {
		case stats = <-statsUpdateC:
			receivedFirstStats = true
			maybeStartInitialDelay()
		case config = <-configUpdateC:
			maybeStartInitialDelay()
		case <-initialDelayDone:
			log.Info("Initial delay complete, doing first report")
			doReport()
			log.Info("First report done, starting ticker")
			baseInterval := interval * 9 / 10
			maxJitter := interval - baseInterval
			ticker := jitter.NewTicker(baseInterval, maxJitter)
			// Disable further kicks from this now-closed channel.
			initialDelayDone = nil
			// Enabled the main ticker loop.
			tickerC = ticker.C
		case <-tickerC:
			doReport()
		}
	}
}

func calculateInitialDelay(numHosts int) time.Duration {
	// Clamp numHosts so that we don't pass anything out-of-range to rand.Intn().
	if numHosts <= 0 {
		numHosts = 1
	}
	if numHosts > 10000 {
		numHosts = 10000
	}
	initialJitter := time.Duration(rand.Intn(numHosts*1000)) * time.Millisecond
	// To avoid spamming the server if we're in a cyclic restart, delay the first report by
	// a few minutes.
	initialDelay := 5*time.Minute + initialJitter
	return initialDelay
}

func ReportUsage(clusterGUID, clusterType, calicoVersion string, stats calc.StatsUpdate) {
	fullURL := calculateURL(clusterGUID, clusterType, calicoVersion, stats)
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

func calculateURL(clusterGUID, clusterType, calicoVersion string, stats calc.StatsUpdate) string {
	if clusterType == "" {
		clusterType = "unknown"
	}
	if calicoVersion == "" {
		calicoVersion = "unknown"
	}
	if clusterGUID == "" {
		clusterGUID = "baddecaf"
	}
	log.WithFields(log.Fields{
		"clusterGUID":   clusterGUID,
		"clusterType":   clusterType,
		"calicoVersion": calicoVersion,
		"stats":         stats,
		"version":       buildinfo.GitVersion,
		"gitRevision":   buildinfo.GitRevision,
	}).Info("Reporting cluster usage/checking for deprecation warnings.")
	queryParams := url.Values{
		"guid":    {clusterGUID},
		"type":    {clusterType},
		"cal_ver": {calicoVersion},
		"size":    {fmt.Sprintf("%v", stats.NumHosts)},
		"weps":    {fmt.Sprintf("%v", stats.NumWorkloadEndpoints)},
		"heps":    {fmt.Sprintf("%v", stats.NumHostEndpoints)},
		"version": {buildinfo.GitVersion},
		"rev":     {buildinfo.GitRevision},
	}
	fullURL := baseURL + queryParams.Encode()
	log.WithField("url", fullURL).Debug("Calculated URL.")
	return fullURL
}
