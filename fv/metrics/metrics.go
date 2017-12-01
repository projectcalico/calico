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

package metrics

import (
	"bufio"
	"net/http"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

func init() {
	http.DefaultClient.Timeout = 1 * time.Second
}

var Port = 9091

func PortString() string {
	return strconv.Itoa(Port)
}

func GetFelixMetric(felixIP, name string) (metric string, err error) {
	var resp *http.Response
	resp, err = http.Get("http://" + felixIP + ":" + PortString() + "/metrics")
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

func GetFelixMetricInt(felixIP, name string) (metric int, err error) {
	s, err := GetFelixMetric(felixIP, name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(s)
}
