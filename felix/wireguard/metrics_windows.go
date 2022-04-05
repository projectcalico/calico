// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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

//go:build windows

package wireguard

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

var _ prometheus.Collector = (*Metrics)(nil)

type Metrics struct {
}

func (collector *Metrics) Describe(_ chan<- *prometheus.Desc) {
}

func (collector *Metrics) Collect(_ chan<- prometheus.Metric) {
}

func MustNewWireguardMetrics() *Metrics {
	wg, err := NewWireguardMetrics()
	if err != nil {
		logrus.Panic(err)
	}
	return wg
}

func NewWireguardMetrics() (*Metrics, error) {
	return &Metrics{}, nil
}
