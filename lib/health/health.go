// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

package health

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// The HealthReport struct has slots for the levels of health that we monitor and aggregate.
type HealthReport struct {
	Live  bool
	Ready bool
}

type reporterState struct {
	// The health indicators that this reporter reports.
	reports HealthReport

	// Expiry time for this reporter's reports.
	timeout time.Duration

	// The most recent report.
	latest HealthReport

	// Time of that most recent report.
	timestamp time.Time
}

// A HealthAggregator receives health reports from individual reporters (which are typically
// components of a particular daemon or application) and aggregates them into an overall health
// summary.  For each monitored kind of health, all of the reporters that report that need to say
// that it is good; for example, to be 'ready' overall, all of the reporters that report readiness
// need to have recently said 'Ready: true'.
type HealthAggregator struct {
	// Mutex to protect concurrent access to this health aggregator.
	mutex *sync.Mutex

	// Map from reporter name to corresponding state.
	reporters map[string]*reporterState
}

// RegisterReporter registers a reporter with a HealthAggregator.  The aggregator uses NAME to
// identify the reporter.  REPORTS indicates the kinds of health that this reporter will report.
// TIMEOUT is the expiry time for this reporter's reports; the implication of which is that the
// reporter should normally refresh its reports well before this time has expired.
func (aggregator *HealthAggregator) RegisterReporter(name string, reports *HealthReport, timeout time.Duration) {
	aggregator.mutex.Lock()
	defer aggregator.mutex.Unlock()
	aggregator.reporters[name] = &reporterState{
		reports:   *reports,
		timeout:   timeout,
		latest:    HealthReport{Live: true},
		timestamp: time.Now(),
	}
	return
}

// Report reports current health from a reporter to a HealthAggregator.  NAME is the reporter's name
// and REPORTS conveys the current status, for each kind of health that the reporter said it was
// going to report when it called RegisterReporter.
func (aggregator *HealthAggregator) Report(name string, report *HealthReport) {
	aggregator.mutex.Lock()
	defer aggregator.mutex.Unlock()
	reporter := aggregator.reporters[name]
	reporter.latest = *report
	reporter.timestamp = time.Now()
	return
}

func NewHealthAggregator() *HealthAggregator {
	return &HealthAggregator{mutex: &sync.Mutex{}, reporters: map[string]*reporterState{}}
}

// Summary calculates the current overall health for a HealthAggregator.
func (aggregator *HealthAggregator) Summary() *HealthReport {
	aggregator.mutex.Lock()
	defer aggregator.mutex.Unlock()

	// In the absence of any reporters, default to indicating that we are both live and ready.
	summary := &HealthReport{Live: true, Ready: true}

	// Now for each reporter...
	for name, reporter := range aggregator.reporters {
		log.WithFields(log.Fields{
			"name":           name,
			"reporter-state": reporter,
		}).Debug("Detailed health state")

		// Reset Live to false if that reporter is registered to report liveness and hasn't
		// recently said that it is live.
		if summary.Live && reporter.reports.Live && (!reporter.latest.Live ||
			(time.Since(reporter.timestamp) > reporter.timeout)) {
			summary.Live = false
		}

		// Reset Ready to false if that reporter is registered to report readiness and
		// hasn't recently said that it is ready.
		if summary.Ready && reporter.reports.Ready && (!reporter.latest.Ready ||
			(time.Since(reporter.timestamp) > reporter.timeout)) {
			summary.Ready = false
		}
	}

	log.WithField("summary", summary).Info("Overall health")
	return summary
}

const (
	// The HTTP status that we use for 'ready' or 'live'.  204 means "No Content: The server
	// successfully processed the request and is not returning any content."  (Kubernetes
	// interpets any 200<=status<400 as 'good'.)
	StatusGood = 204

	// The HTTP status that we use for 'not ready' or 'not live'.  503 means "Service
	// Unavailable: The server is currently unavailable (because it is overloaded or down for
	// maintenance). Generally, this is a temporary state."  (Kubernetes interpets any
	// status>=400 as 'bad'.)
	StatusBad = 503
)

// ServeHTTP publishes the current overall liveness and readiness at http://*:PORT/liveness and
// http://*:PORT/readiness respectively.  A GET request on those URLs returns StatusGood or
// StatusBad, according to the current overall liveness or readiness.  These endpoints are designed
// for use by Kubernetes liveness and readiness probes.
func (aggregator *HealthAggregator) ServeHTTP(port int) {

	log.WithField("port", port).Info("Starting health endpoints")
	http.HandleFunc("/readiness", func(rsp http.ResponseWriter, req *http.Request) {
		log.Debug("GET /readiness")
		status := StatusBad
		if aggregator.Summary().Ready {
			log.Debug("Felix is ready")
			status = StatusGood
		}
		rsp.WriteHeader(status)
	})
	http.HandleFunc("/liveness", func(rsp http.ResponseWriter, req *http.Request) {
		log.Debug("GET /liveness")
		status := StatusBad
		if aggregator.Summary().Live {
			log.Debug("Felix is live")
			status = StatusGood
		}
		rsp.WriteHeader(status)
	})
	for {
		err := http.ListenAndServe(fmt.Sprintf(":%v", port), nil)
		log.WithError(err).Error(
			"Readiness endpoint failed, trying to restart it...")
		time.Sleep(1 * time.Second)
	}
}
