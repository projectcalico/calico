// Copyright (c) 2023 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package metricsserver

import (
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

func ServePrometheusMetricsForever(host string, port int) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	addr := fmt.Sprintf("[%v]:%v", host, port)

	for {
		logrus.WithFields(logrus.Fields{
			"host": host,
			"port": port,
		}).Info("Starting prometheus metrics endpoint")
		err := http.ListenAndServe(addr, mux)
		logrus.WithError(err).Error(
			"Prometheus metrics endpoint failed, trying to restart it...")
		time.Sleep(1 * time.Second)
	}
}
