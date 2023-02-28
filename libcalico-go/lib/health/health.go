// Copyright (c) 2017-2019 Tigera, Inc. All rights reserved.
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
	"bytes"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/olekukonko/tablewriter"
	log "github.com/sirupsen/logrus"
)

var (
	globalOverridesLock    sync.Mutex
	globalTimeoutOverrides map[string]time.Duration
)

func SetGlobalTimeoutOverrides(overrides map[string]time.Duration) {
	overridesCopy := map[string]time.Duration{}
	for k, v := range overrides {
		overridesCopy[k] = v
	}
	globalOverridesLock.Lock()
	defer globalOverridesLock.Unlock()
	globalTimeoutOverrides = overrides
}

func GlobalOverride(name string) *time.Duration {
	globalOverridesLock.Lock()
	defer globalOverridesLock.Unlock()
	override, ok := globalTimeoutOverrides[name]
	if ok {
		return &override
	}
	return nil
}

// The HealthReport struct has slots for the levels of health that we monitor and aggregate.
type HealthReport struct {
	Live   bool
	Ready  bool
	Detail string
}

func (h *HealthReport) String() string {
	var parts []string
	if h.Live {
		parts = append(parts, "live")
	}
	if h.Ready {
		parts = append(parts, "ready")
	}
	if h.Detail != "" {
		parts = append(parts, "detail="+h.Detail)
	}
	return strings.Join(parts, ",")
}

type reporterState struct {
	// The reporter's name.
	name string

	// The health indicators that this reporter reports.
	reports HealthReport

	// Expiry time for this reporter's reports.  Zero means that reports never expire.
	timeout time.Duration

	// The most recent report.
	latest HealthReport

	// Time of that most recent report.
	timestamp time.Time
}

func (r *reporterState) String() string {
	var timeoutStr string
	if r.timeout == 0 {
		timeoutStr = "none"
	} else {
		timeoutStr = r.timeout.String()
	}
	timestampStr := "-"
	agoStr := "-"
	if !r.timestamp.IsZero() {
		timestampStr = r.timestamp.Format("15:04:05")
		agoStr = fmt.Sprintf("%.1f", time.Since(r.timestamp).Seconds())
	}
	return fmt.Sprintf("health.reporterState{name:%q, reports:%q, latest:%q, timestamp:%s(%ss ago) timeout:%s}",
		r.name, r.reports.String(), r.latest.String(), timestampStr, agoStr, timeoutStr)
}

func (r *reporterState) readiness() (bool, string) {
	if !r.reports.Ready {
		return true, "-"
	}
	if r.TimedOut() {
		return false, "timed out"
	}
	if r.latest.Ready {
		return true, "reporting ready"
	}
	return false, "reporting non-ready"
}

func (r *reporterState) liveness() (bool, string) {
	if !r.reports.Live {
		return true, "-"
	}
	if r.TimedOut() {
		return false, "timed out"
	}
	if r.latest.Live {
		return true, "reporting live"
	}
	return false, "reporting non-live"
}

// TimedOut checks whether the reporter is due for another report. This is the case when
// the reports are configured to expire and the time since the last report exceeds the report timeout duration.
func (r *reporterState) TimedOut() bool {
	timeout := r.timeout
	if o := GlobalOverride(r.name); o != nil {
		timeout = *o
	}
	return timeout != 0 && time.Since(r.timestamp) > timeout
}

// A HealthAggregator receives health reports from individual reporters (which are typically
// components of a particular daemon or application) and aggregates them into an overall health
// summary.  For each monitored kind of health, all of the reporters that report that need to say
// that it is good; for example, to be 'ready' overall, all of the reporters that report readiness
// need to have recently said 'Ready: true'.
type HealthAggregator struct {
	// Mutex to protect concurrent access to this health aggregator.
	mutex *sync.Mutex

	// The previous health summary report which is cached so that we log only when the overall health report changes.
	lastReport *HealthReport

	// Map from reporter name to corresponding state.
	reporters map[string]*reporterState

	// HTTP server mux.  This is where we register handlers for particular URLs.
	httpServeMux *http.ServeMux

	// HTTP server.  Non-nil when there should be a server running.
	httpServer *http.Server

	// Track whether we have ever previously reported as ready overall.
	everReady bool
}

// RegisterReporter registers a reporter with a HealthAggregator.  The aggregator uses NAME to
// identify the reporter.  REPORTS indicates the kinds of health that this reporter will report.
// TIMEOUT is the expiry time for this reporter's reports; the implication of which is that the
// reporter should normally refresh its reports well before this time has expired.
func (aggregator *HealthAggregator) RegisterReporter(name string, reports *HealthReport, timeout time.Duration) {
	aggregator.mutex.Lock()
	defer aggregator.mutex.Unlock()
	aggregator.reporters[name] = &reporterState{
		name:      name,
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

	reports := aggregator.reporters[name].reports
	logCxt := log.WithFields(log.Fields{
		"name":      name,
		"newReport": formatReport(&reports, report),
		"oldReport": formatReport(&reports, &reporter.latest),
	})

	if reporter.latest != *report {
		logCxt.Info("Health of component changed")
		reporter.latest = *report
	}
	reporter.timestamp = time.Now()
	return
}

func formatReport(reports, report *HealthReport) string {
	var parts []string

	if reports.Live {
		if report.Live {
			parts = append(parts, "live")
		} else {
			parts = append(parts, "non-live")
		}
	}
	if reports.Ready {
		if report.Ready {
			parts = append(parts, "ready")
		} else {
			parts = append(parts, "non-ready")
		}
	}
	return strings.Join(parts, ",")
}

func NewHealthAggregator() *HealthAggregator {
	aggregator := &HealthAggregator{
		mutex:        &sync.Mutex{},
		lastReport:   &HealthReport{},
		reporters:    map[string]*reporterState{},
		httpServeMux: http.NewServeMux(),
	}
	aggregator.httpServeMux.HandleFunc("/readiness", func(rsp http.ResponseWriter, req *http.Request) {
		log.Debug("GET /readiness")
		summary := aggregator.Summary()
		genResponse(rsp, "ready", summary.Ready, summary.Detail)
	})
	aggregator.httpServeMux.HandleFunc("/liveness", func(rsp http.ResponseWriter, req *http.Request) {
		log.Debug("GET /liveness")
		summary := aggregator.Summary()
		genResponse(rsp, "live", summary.Live, summary.Detail)
	})
	return aggregator
}

func genResponse(rsp http.ResponseWriter, quality string, state bool, detail string) {
	status := StatusBad
	if state {
		log.Debug("Health: " + quality)
		status = StatusGood
		if len(detail) == 0 {
			status = StatusGoodNoContent
		}
	}
	rsp.WriteHeader(status)
	rsp.Write([]byte(detail))
}

// Summary calculates the current overall health for a HealthAggregator.
func (aggregator *HealthAggregator) Summary() *HealthReport {
	aggregator.mutex.Lock()
	defer aggregator.mutex.Unlock()

	// In the absence of any reporters, default to indicating that we are both live and ready.
	summary := &HealthReport{Live: true, Ready: true}

	// Prepare a table to report detail.
	var buf bytes.Buffer
	table := tablewriter.NewWriter(&buf)
	table.SetHeader([]string{"COMPONENT", "TIMEOUT", "LIVENESS", "READINESS", "DETAIL"})
	componentData := map[string][]string{}
	componentNames := []string(nil)

	// Now for each reporter...
	for _, reporter := range aggregator.reporters {
		log.WithField("reporter", reporter).Debug("Checking state of reporter")
		live, livenessStr := reporter.liveness()
		if !live {
			log.WithField("name", reporter.name).Warnf("Reporter is not live: %v.", livenessStr)
			summary.Live = false
		}
		ready, readinessStr := reporter.readiness()
		if !ready {
			if aggregator.everReady {
				log.WithField("name", reporter.name).Warnf("Reporter is not ready: %v.", readinessStr)
			} else {
				log.WithField("name", reporter.name).Infof("Reporter is not ready: %v.", readinessStr)
			}
			summary.Ready = false
		}
		componentNames = append(componentNames, reporter.name)

		suffix := ""
		timeout := reporter.timeout
		if ov := GlobalOverride(reporter.name); ov != nil {
			suffix = " (override)"
			timeout = *ov
		}
		var timeoutStr string
		if timeout == 0 {
			timeoutStr = "-"
		} else {
			timeoutStr = timeout.String()
		}
		timeoutStr += suffix

		componentData[reporter.name] = []string{
			reporter.name,
			timeoutStr,
			livenessStr,
			readinessStr,
			reporter.latest.Detail,
		}
	}

	// Render the component data ordered by name.
	sort.Strings(componentNames)
	for _, name := range componentNames {
		table.Append(componentData[name])
	}
	table.Render()

	summary.Detail = strings.TrimSpace(buf.String())
	log.Debugf("Calculated health summary: live=%v ready=%v\n%s", summary.Live, summary.Ready, summary.Detail)

	// Summary status has changed so update previous status and log.
	if aggregator.lastReport == nil || *summary != *aggregator.lastReport {
		aggregator.lastReport = summary
		log.Infof("Overall health status changed: live=%v ready=%v\n%s", summary.Live, summary.Ready, summary.Detail)
	}

	if summary.Ready {
		aggregator.everReady = true
	}

	return summary
}

const (
	// The HTTP status that we use for 'ready' or 'live', with detail content.  (Kubernetes
	// interprets any 200<=status<400 as 'good'.)
	StatusGood = 200

	// The HTTP status that we use for 'ready' or 'live', without any detail content.  204 means
	// "No Content: The server successfully processed the request and is not returning any
	// content."  (Kubernetes interprets any 200<=status<400 as 'good'.)
	StatusGoodNoContent = 204

	// The HTTP status that we use for 'not ready' or 'not live'.  503 means "Service
	// Unavailable: The server is currently unavailable (because it is overloaded or down for
	// maintenance). Generally, this is a temporary state."  (Kubernetes interprets any
	// status>=400 as 'bad'.)
	StatusBad = 503
)

// ServeHTTP publishes the current overall liveness and readiness at http://HOST:PORT/liveness and
// http://HOST:PORT/readiness respectively.  A GET request on those URLs returns StatusGood or
// StatusBad, according to the current overall liveness or readiness.  These endpoints are designed
// for use by Kubernetes liveness and readiness probes.
func (aggregator *HealthAggregator) ServeHTTP(enabled bool, host string, port int) {
	aggregator.mutex.Lock()
	defer aggregator.mutex.Unlock()
	if enabled {
		logCxt := log.WithFields(log.Fields{
			"host": host,
			"port": port,
		})
		if aggregator.httpServer != nil {
			logCxt.Info("Health enabled.  Server is already running.")
			return
		}
		logCxt.Info("Health enabled.  Starting server.")
		aggregator.httpServer = &http.Server{
			Addr:    net.JoinHostPort(host, strconv.Itoa(port)),
			Handler: aggregator.httpServeMux,
		}
		go func() {
			for {
				server := aggregator.getHTTPServer()
				if server == nil {
					// HTTP serving is now disabled.
					break
				}
				err := server.ListenAndServe()
				log.WithError(err).Error(
					"Health endpoint failed, trying to restart it...")
				time.Sleep(1 * time.Second)
			}
		}()
	} else {
		if aggregator.httpServer != nil {
			log.Info("Health disabled.  Stopping server.")
			_ = aggregator.httpServer.Close()
			aggregator.httpServer = nil
		}
	}
}

func (aggregator *HealthAggregator) getHTTPServer() *http.Server {
	aggregator.mutex.Lock()
	defer aggregator.mutex.Unlock()
	return aggregator.httpServer
}
