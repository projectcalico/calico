// Copyright (c) 2016-2026 Tigera, Inc. All rights reserved.
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

package daemon

import (
	"os"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/projectcalico/calico/lib/std/log"
	"github.com/projectcalico/calico/typha/pkg/config"
)

// Prometheus counters preserved from the pre-migration metric names.
var (
	counterTyphaLogsDropped = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "typha_logs_dropped",
		Help: "Number of logs dropped because the output stream was blocked.",
	})
	counterTyphaLogErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "typha_log_errors",
		Help: "Number of errors encountered while logging.",
	})
)

func init() {
	prometheus.MustRegister(counterTyphaLogsDropped, counterTyphaLogErrors)
}

// ConfigureEarlyLogging sets the component to "typha" and parses the log level
// from TYPHA_EARLYLOGSEVERITYSCREEN (early-only) or TYPHA_LOGSEVERITYSCREEN.
// Exported because the Daemon struct injects it as a function value.
func ConfigureEarlyLogging() {
	log.SetComponent("typha")

	raw := os.Getenv("TYPHA_EARLYLOGSEVERITYSCREEN")
	if raw == "" {
		raw = os.Getenv("TYPHA_LOGSEVERITYSCREEN")
	}

	level := log.ErrorLevel
	if raw != "" {
		parsed, err := log.ParseLevel(raw)
		if err == nil {
			level = parsed
		} else {
			log.WithError(err).Error("Failed to parse early log level, defaulting to error.")
		}
	}
	log.SetLevel(level)
	log.Infof("Early screen log level set to %v", level)
}

// ConfigureLogging installs the full multi-destination logging configuration
// once typha's config has been resolved. Exported because the Daemon struct
// injects it as a function value.
func ConfigureLogging(configParams *config.Config) {
	opts := log.Options{
		Component: "typha",
		// Typha writes through the background hook from a single goroutine,
		// so the standard logger's internal mutex isn't needed.
		SingleThreaded: true,
		Counters: log.Counters{
			DroppedLogs: counterTyphaLogsDropped,
			WriteErrors: counterTyphaLogErrors,
		},
	}
	if configParams.LogSeverityScreen != "" {
		opts.Screen = &log.ScreenConfig{
			Level: log.SafeParseLevel(configParams.LogSeverityScreen),
		}
	}
	if configParams.LogSeverityFile != "" && configParams.LogFilePath != "" {
		opts.File = &log.FileConfig{
			Level: log.SafeParseLevel(configParams.LogSeverityFile),
			Path:  configParams.LogFilePath,
		}
	}
	if configParams.LogSeveritySys != "" {
		opts.Syslog = &log.SyslogConfig{
			Level: log.SafeParseLevel(configParams.LogSeveritySys),
			Tag:   "calico-typha",
		}
	}
	if err := log.Configure(opts); err != nil {
		log.WithError(err).Warn("Some logging destinations failed to open; continuing with the destinations that did open.")
	}
}
