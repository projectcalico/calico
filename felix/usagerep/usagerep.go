// Copyright (c) 2016-2018 Tigera, Inc. All rights reserved.
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
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/buildinfo"
	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/jitter"
)

const (
	DefaultBaseURL = "https://usage.projectcalico.org/UsageCheck/calicoVersionCheck?"
)

func New(
	staticItems StaticItems,
	initialDelay time.Duration,
	interval time.Duration,
	statsUpdateC <-chan calc.StatsUpdate,
	configUpdateC <-chan map[string]string,
) *UsageReporter {
	return &UsageReporter{
		staticItems:   staticItems,
		interval:      interval,
		statsUpdateC:  statsUpdateC,
		configUpdateC: configUpdateC,
		InitialDelay:  initialDelay,
		BaseURL:       DefaultBaseURL,
		httpClient: http.Client{
			// Short timeout to make sure we don't block on the request, leaving the channels
			// starved for too long.
			Timeout: 5 * time.Second,
		},
	}
}

type StaticItems struct {
	KubernetesVersion string
}

type UsageReporter struct {
	staticItems StaticItems

	interval      time.Duration
	statsUpdateC  <-chan calc.StatsUpdate
	configUpdateC <-chan map[string]string

	InitialDelay time.Duration
	BaseURL      string
	httpClient   http.Client
}

func (u *UsageReporter) PeriodicallyReportUsage(ctx context.Context) {
	var stats calc.StatsUpdate
	var config map[string]string
	var receivedFirstStats bool
	var tickerC <-chan time.Time
	initialDelayStarted := false
	initialDelayDone := make(chan struct{})

	maybeStartInitialDelay := func() {
		if !receivedFirstStats || config == nil || initialDelayStarted {
			return
		}

		// To avoid thundering herd, inject some startup jitter.
		initialDelay := u.calculateInitialDelay(stats.NumHosts)
		go func() {
			log.WithField("delay", initialDelay).Info("Waiting before first check-in")
			time.Sleep(initialDelay)
			close(initialDelayDone)
		}()
		initialDelayStarted = true
	}

	doReport := func() {
		alpEnabled := (config["PolicySyncPathPrefix"] != "")
		bpfEnabled := (config["BPFEnabled"] == "true")
		u.reportUsage(config["ClusterGUID"], config["ClusterType"], config["CalicoVersion"], alpEnabled, bpfEnabled, stats)
	}

	var ticker *jitter.Ticker
	for {
		select {
		case stats = <-u.statsUpdateC:
			log.WithField("stats", stats).Debug("Received stats update")
			receivedFirstStats = true
			maybeStartInitialDelay()
		case config = <-u.configUpdateC:
			log.WithField("config", config).Debug("Received config update")
			maybeStartInitialDelay()
		case <-initialDelayDone:
			log.Info("Initial delay complete, doing first report")
			doReport()
			log.Info("First report done, starting ticker")
			baseInterval := u.interval * 9 / 10
			maxJitter := u.interval - baseInterval
			ticker = jitter.NewTicker(baseInterval, maxJitter)
			// Disable further kicks from this now-closed channel.
			initialDelayDone = nil
			// Enabled the main ticker loop.
			tickerC = ticker.C
		case <-tickerC:
			log.Debug("Received tick")
			doReport()
		case <-ctx.Done():
			log.Warn("Context stopped")
			if ticker != nil {
				ticker.Stop()
			}
			return
		}
	}
}

func (u *UsageReporter) calculateInitialDelay(numHosts int) time.Duration {
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
	initialDelay := u.InitialDelay + initialJitter
	return initialDelay
}

func (u *UsageReporter) reportUsage(clusterGUID, clusterType, calicoVersion string, alpEnabled bool, bpfEnabled bool, stats calc.StatsUpdate) {
	fullURL := u.calculateURL(clusterGUID, clusterType, calicoVersion, alpEnabled, bpfEnabled, stats)
	resp, err := u.httpClient.Get(fullURL)
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

func (u *UsageReporter) calculateURL(clusterGUID, clusterType, calicoVersion string, alpEnabled bool, bpfEnabled bool, stats calc.StatsUpdate) string {
	var kubernetesVersion string

	if clusterType == "" {
		clusterType = "unknown"
	}
	if calicoVersion == "" {
		calicoVersion = "unknown"
	}
	if u.staticItems.KubernetesVersion == "" {
		kubernetesVersion = "unknown"
	} else {
		kubernetesVersion = u.staticItems.KubernetesVersion
	}
	if clusterGUID == "" {
		clusterGUID = "baddecaf"
	}
	if bpfEnabled {
		clusterType = clusterType + ",bpf"
	}
	log.WithFields(log.Fields{
		"clusterGUID":       clusterGUID,
		"clusterType":       clusterType,
		"calicoVersion":     calicoVersion,
		"kubernetesVersion": kubernetesVersion,
		"alpEnabled":        alpEnabled,
		"stats":             stats,
		"version":           buildinfo.GitVersion,
		"gitRevision":       buildinfo.GitRevision,
	}).Info("Reporting cluster usage/checking for deprecation warnings.")
	queryParams := url.Values{
		"guid":         {clusterGUID},
		"type":         {clusterType},
		"cal_ver":      {calicoVersion},
		"k8s_ver":      {kubernetesVersion},
		"alp":          {fmt.Sprint(alpEnabled)},
		"size":         {fmt.Sprint(stats.NumHosts)},
		"weps":         {fmt.Sprint(stats.NumWorkloadEndpoints)},
		"heps":         {fmt.Sprint(stats.NumHostEndpoints)},
		"version":      {buildinfo.GitVersion},
		"rev":          {buildinfo.GitRevision},
		"policies":     {fmt.Sprint(stats.NumPolicies)},
		"profiles":     {fmt.Sprint(stats.NumProfiles)},
		"alp_policies": {fmt.Sprint(stats.NumALPPolicies)},
	}
	fullURL := u.BaseURL + queryParams.Encode()
	log.WithField("url", fullURL).Debug("Calculated URL.")
	return fullURL
}
