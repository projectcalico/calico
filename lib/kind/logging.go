// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package kind

import (
	"fmt"

	kindlog "sigs.k8s.io/kind/pkg/log"

	"github.com/projectcalico/calico/lib/std/log"
)

// kindLoggerAdapter implements sigs.k8s.io/kind/pkg/log.Logger on top of the
// lib/std/log interface. Kind's create-cluster step takes 60-120s and emits
// progress through this logger — without forwarding it, the test output sits
// silent during cluster bring-up.
//
// Kind's logger is printf-shaped (Warnf/Errorf/Infof) while lib/std/log is
// slog-shaped (message + key/value pairs), so the formatting variants render
// the message themselves with fmt.Sprintf before handing it over.
type kindLoggerAdapter struct {
	logger log.Logger
}

func (k kindLoggerAdapter) Warn(msg string) { k.logger.Warn(msg) }
func (k kindLoggerAdapter) Warnf(format string, args ...any) {
	k.logger.Warn(fmt.Sprintf(format, args...))
}
func (k kindLoggerAdapter) Error(msg string) { k.logger.Error(msg) }
func (k kindLoggerAdapter) Errorf(format string, args ...any) {
	k.logger.Error(fmt.Sprintf(format, args...))
}

func (k kindLoggerAdapter) V(level kindlog.Level) kindlog.InfoLogger {
	// Kind levels: 0 = user-facing, 1+ = debug. Only forward V(0) by
	// default — anything noisier than that floods test output.
	return kindInfoLogger{logger: k.logger, enabled: level <= 0}
}

type kindInfoLogger struct {
	logger  log.Logger
	enabled bool
}

func (k kindInfoLogger) Info(msg string) {
	if k.enabled {
		k.logger.Info(msg)
	}
}

func (k kindInfoLogger) Infof(format string, args ...any) {
	if k.enabled {
		k.logger.Info(fmt.Sprintf(format, args...))
	}
}

func (k kindInfoLogger) Enabled() bool { return k.enabled }
