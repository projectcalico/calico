package health

//import (
//	"time"
//
//	"github.com/projectcalico/calico/lib/std/log"
//
//	"github.com/projectcalico/calico/lib/std/clock"
//)
//
//type Reporter interface {
//	BroadcastLiveness(bool, ...string)
//	BroadcastReadiness(bool, ...string)
//	IndicateLiveness(b bool, messages ...string)
//	IndicateReadiness(b bool, messages ...string)
//	LivenessTicker() clock.Ticker
//}
//
//type logReporter struct {
//	log              log.Entry
//	livenessInterval time.Duration
//}
//
//func (reporter *logReporter) LivenessTicker() clock.Ticker {
//	return clock.NewTicker(reporter.livenessInterval)
//}
//
//func (reporter *logReporter) BroadcastLiveness(b bool, messages ...string) {
//	log.WithField("live", b).WithField("messages", messages).Debugf("Broadcasting liveness status.")
//}
//
//func (reporter *logReporter) BroadcastReadiness(b bool, messages ...string) {
//	log.WithField("ready", b).WithField("messages", messages).Debugf("Broadcasting readiness status.")
//}
//
//func (reporter *logReporter) IndicateLiveness(b bool, messages ...string) {
//	log.WithField("live", b).WithField("messages", messages).Debugf("Hinting liveness status.")
//}
//
//func (reporter *logReporter) IndicateReadiness(b bool, messages ...string) {
//	log.WithField("ready", b).WithField("messages", messages).Debugf("Hinting readiness status.")
//}
//
//func NewLogReporter(entry log.Entry, livenessInterval time.Duration) Reporter {
//	return &logReporter{
//		log:              entry,
//		livenessInterval: livenessInterval,
//	}
//}
