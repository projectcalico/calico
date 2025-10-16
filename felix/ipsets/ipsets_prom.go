// Copyright (c) 2017-2023 Tigera, Inc. All rights reserved.
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

//go:build linux

package ipsets

import (
	"github.com/prometheus/client_golang/prometheus"

	cprometheus "github.com/projectcalico/calico/libcalico-go/lib/prometheus"
)

var (
	gaugeVecNumCalicoIpsets = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "felix_ipsets_calico",
		Help: "Number of active Calico IP sets.",
	}, []string{"ip_version"})
	gaugeNumTotalIpsets = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_ipsets_total",
		Help: "Total number of active IP sets.",
	})
	countNumIPSetCalls = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_ipset_calls",
		Help: "Number of ipset commands executed.",
	})
	countNumIPSetErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_ipset_errors",
		Help: "Number of ipset command failures.",
	})
	countNumIPSetLinesExecuted = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_ipset_lines_executed",
		Help: "Number of ipset operations executed.",
	})
	summaryExecStart = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_exec_time_micros",
		Help: "Summary of time taken to fork/exec child processes",
	})
)

func init() {
	prometheus.MustRegister(gaugeVecNumCalicoIpsets)
	prometheus.MustRegister(gaugeNumTotalIpsets)
	prometheus.MustRegister(countNumIPSetCalls)
	prometheus.MustRegister(countNumIPSetErrors)
	prometheus.MustRegister(countNumIPSetLinesExecuted)
	prometheus.MustRegister(summaryExecStart)
}
