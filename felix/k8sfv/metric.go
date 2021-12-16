// Copyright (c) 2017,2019 Tigera, Inc. All rights reserved.
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
	"bufio"
	"net/http"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

func getFelixMetric(name string) (metric string, err error) {
	var resp *http.Response
	resp, err = http.Get("http://" + felixIP + ":9091/metrics")
	if err != nil {
		return
	}
	log.WithField("resp", resp).Debug("Metric response")
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		log.WithField("line", line).Debug("Line")
		if strings.HasPrefix(line, name) {
			log.WithField("line", line).Info("Line")
			metric = strings.TrimSpace(strings.TrimPrefix(line, name))
			break
		}
	}
	err = scanner.Err()
	return
}

func getFelixFloatMetricOrPanic(name string) float64 {
	metricS, err := getFelixMetric(name)
	panicIfError(err)
	metric, err := strconv.ParseFloat(metricS, 64)
	panicIfError(err)
	return metric
}

func getFelixIntMetric(name string) (int64, error) {
	metricS, err := getFelixMetric(name)
	if err != nil {
		return -1, err
	}
	metric, err := strconv.ParseInt(metricS, 10, 64)
	if err != nil {
		return -1, err
	}
	return metric, nil
}

func getNumEndpoints() (int64, error) {
	s, err := getFelixMetric("felix_cluster_num_workload_endpoints")
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(s, 10, 64)
}

func getNumEndpointsDefault(def int64) func() int64 {
	return func() int64 {
		numEndpoints, err := getNumEndpoints()
		if err != nil {
			numEndpoints = def
		}
		return numEndpoints
	}
}
