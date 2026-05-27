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

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/lib/std/log"
)

// Prometheus counters for log delivery health. Names are preserved from the
// pre-migration metric so existing dashboards keep working.
var (
	counterLogsDropped = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_logs_dropped",
		Help: "Number of logs dropped because the output stream was blocked.",
	})
	counterLogErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_log_errors",
		Help: "Number of errors encountered while logging.",
	})
)

func init() {
	prometheus.MustRegister(counterLogsDropped, counterLogErrors)
}

// configureEarlyLogging sets up logging before felix has loaded its full
// config. The component prefix is fixed to "felix" and the log level is
// taken from FELIX_EARLYLOGSEVERITYSCREEN (early-only) or
// FELIX_LOGSEVERITYSCREEN (the config-owned variable). Default is Error.
func configureEarlyLogging() {
	log.SetComponent("felix")

	raw := os.Getenv("FELIX_EARLYLOGSEVERITYSCREEN")
	if raw == "" {
		raw = os.Getenv("FELIX_LOGSEVERITYSCREEN")
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

// configureLogging installs the full multi-destination logging configuration
// once felix's config has been resolved. Any errors opening the file or
// connecting to syslog are returned for the caller to log; the logger
// continues to function via any destinations that did open.
func configureLogging(configParams *config.Config) error {
	opts := log.Options{
		Component:               "felix",
		DebugFilenameRegex:      configParams.LogDebugFilenameRegex,
		DebugDisableLogDropping: configParams.DebugDisableLogDropping,
		Counters: log.Counters{
			DroppedLogs: counterLogsDropped,
			WriteErrors: counterLogErrors,
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
			Tag:   "calico-felix",
		}
	}

	return log.Configure(opts)
}
