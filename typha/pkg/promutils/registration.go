// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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

package promutils

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/typha/pkg/syncproto"
)

// GetOrRegister tries to register the given collector with Prometheus' DefaultRegisterer.  If the registration fails
// because an identical collector is already registered then it returns the existing collector.  Otherwise, it
// returns the input collector.  Panics on other errors.
func GetOrRegister[T prometheus.Collector](collector T) T {
	err := prometheus.DefaultRegisterer.Register(collector)
	if err != nil {
		if err, ok := err.(prometheus.AlreadyRegisteredError); ok {
			return err.ExistingCollector.(T)
		} else {
			logrus.WithError(err).WithField("collector", collector).Panic("Failed to register prometheus collector.")
		}
	}
	return collector
}

func PreCreateCounterPerSyncer(cv *prometheus.CounterVec) {
	for _, st := range syncproto.AllSyncerTypes {
		cv.WithLabelValues(string(st))
	}
}

func PreCreateGaugePerSyncer(cv *prometheus.GaugeVec) {
	for _, st := range syncproto.AllSyncerTypes {
		cv.WithLabelValues(string(st))
	}
}
