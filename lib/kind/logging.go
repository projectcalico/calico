// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package kind

import (
	log "github.com/sirupsen/logrus"
	kindlog "sigs.k8s.io/kind/pkg/log"
)

// kindLoggerAdapter implements sigs.k8s.io/kind/pkg/log.Logger on top of
// logrus. Kind's create-cluster step takes 60-120s and emits progress
// through this logger — without forwarding it, the test output sits
// silent during cluster bring-up.
type kindLoggerAdapter struct {
	entry *log.Entry
}

func (k kindLoggerAdapter) Warn(msg string)                   { k.entry.Warn(msg) }
func (k kindLoggerAdapter) Warnf(format string, args ...any)  { k.entry.Warnf(format, args...) }
func (k kindLoggerAdapter) Error(msg string)                  { k.entry.Error(msg) }
func (k kindLoggerAdapter) Errorf(format string, args ...any) { k.entry.Errorf(format, args...) }

func (k kindLoggerAdapter) V(level kindlog.Level) kindlog.InfoLogger {
	// Kind levels: 0 = user-facing, 1+ = debug. Only forward V(0) by
	// default — anything noisier than that floods test output.
	return kindInfoLogger{entry: k.entry, enabled: level <= 0}
}

type kindInfoLogger struct {
	entry   *log.Entry
	enabled bool
}

func (k kindInfoLogger) Info(msg string) {
	if k.enabled {
		k.entry.Info(msg)
	}
}

func (k kindInfoLogger) Infof(format string, args ...any) {
	if k.enabled {
		k.entry.Infof(format, args...)
	}
}

func (k kindInfoLogger) Enabled() bool { return k.enabled }
