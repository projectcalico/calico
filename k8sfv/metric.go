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

package main

import (
	"bufio"
	"net/http"
	"strconv"
	"strings"

	log "github.com/Sirupsen/logrus"
)

func getFelixMetric(name string) (metric string) {
	resp, err := http.Get("http://" + felixIP + ":9091/metrics")
	panicIfError(err)
	log.WithField("resp", resp).Debug("Metric response")
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		log.WithField("line", line).Debug("Line")
		if strings.HasPrefix(line, name) {
			metric = strings.TrimSpace(strings.TrimPrefix(line, name))
			break
		}
	}
	panicIfError(scanner.Err())
	return
}

func getFelixFloatMetric(name string) float64 {
	metric, err := strconv.ParseFloat(getFelixMetric(name), 64)
	panicIfError(err)
	return metric
}
