// Copyright (c) 2017-2021 Tigera, Inc. All rights reserved.
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

package dataplane

import (
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/projectcalico/calico/felix/config"
	windataplane "github.com/projectcalico/calico/felix/dataplane/windows"
	"github.com/projectcalico/calico/felix/dataplane/windows/hns"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
)

func StartDataplaneDriver(configParams *config.Config,
	healthAggregator *health.HealthAggregator,
	configChangedRestartCallback func(),
	fatalErrorCallback func(error),
	k8sClientSet *kubernetes.Clientset) (DataplaneDriver, *exec.Cmd) {
	log.Info("Using Windows dataplane driver.")

	dpConfig := windataplane.Config{
		IPv6Enabled:      configParams.Ipv6Support,
		HealthAggregator: healthAggregator,

		Hostname:     configParams.FelixHostname,
		VXLANEnabled: configParams.Encapsulation.VXLANEnabled,
		VXLANID:      configParams.VXLANVNI,
		VXLANPort:    configParams.VXLANPort,
	}

	winDP := windataplane.NewWinDataplaneDriver(hns.API{}, dpConfig)
	winDP.Start()

	return winDP, nil
}

func SupportsBPF() error {
	return fmt.Errorf("BPF dataplane is not supported on Windows")
}

func ServePrometheusMetrics(configParams *config.Config) {
	log.WithFields(log.Fields{
		"host": configParams.PrometheusMetricsHost,
		"port": configParams.PrometheusMetricsPort,
	}).Info("Starting prometheus metrics endpoint")
	if configParams.PrometheusGoMetricsEnabled && configParams.PrometheusProcessMetricsEnabled {
		log.Info("Including Golang, and Process metrics")
	} else {
		if !configParams.PrometheusGoMetricsEnabled {
			log.Info("Discarding Golang metrics")
			prometheus.Unregister(collectors.NewGoCollector())
		}
		if !configParams.PrometheusProcessMetricsEnabled {
			log.Info("Discarding process metrics")
			prometheus.Unregister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
		}
	}
	http.Handle("/metrics", promhttp.Handler())
	addr := net.JoinHostPort(configParams.PrometheusMetricsHost, strconv.Itoa(configParams.PrometheusMetricsPort))
	for {
		err := http.ListenAndServe(addr, nil)
		log.WithError(err).Error(
			"Prometheus metrics endpoint failed, trying to restart it...")
		time.Sleep(1 * time.Second)
	}
}
