package health

import (
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/lib/std/timeutil"
)

type Reporter interface {
	BroadcastLiveness(bool, ...string)
	BroadcastReadiness(bool, ...string)
	IndicateLiveness(b bool, messages ...string)
	IndicateReadiness(b bool, messages ...string)
	LivenessTicker() timeutil.Ticker
}

type logReporter struct {
	log              *logrus.Entry
	livenessInterval time.Duration
}

func (reporter *logReporter) LivenessTicker() timeutil.Ticker {
	return timeutil.NewTicker(reporter.livenessInterval)
}

func (reporter *logReporter) BroadcastLiveness(b bool, messages ...string) {
	logrus.WithField("live", b).WithField("messages", messages).Debugf("Broadcasting liveness status.")
}

func (reporter *logReporter) BroadcastReadiness(b bool, messages ...string) {
	logrus.WithField("ready", b).WithField("messages", messages).Debugf("Broadcasting readiness status.")
}

func (reporter *logReporter) IndicateLiveness(b bool, messages ...string) {
	logrus.WithField("live", b).WithField("messages", messages).Debugf("Hinting liveness status.")
}

func (reporter *logReporter) IndicateReadiness(b bool, messages ...string) {
	logrus.WithField("ready", b).WithField("messages", messages).Debugf("Hinting readiness status.")
}

func NewLogReporter(entry *logrus.Entry, livenessInterval time.Duration) Reporter {
	return &logReporter{
		log:              entry,
		livenessInterval: livenessInterval,
	}
}
