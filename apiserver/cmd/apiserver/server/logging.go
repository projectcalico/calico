package server

import (
	"fmt"
	"os"
	"strconv"

	"github.com/go-logr/logr"
	"github.com/sirupsen/logrus"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

// logrusLevel sets LOG_LEVEL and if not defined will set it based on klog verbosity
// v=0 --> ERROR
// v=1 --> WARN
// v=2 --> INFO
// v=3-6 --> DEBUG
// v=7-9 --> TRACE
func logrusLevel() logrus.Level {
	if env := os.Getenv("LOG_LEVEL"); env != "" {
		return logutils.SafeParseLogLevel(env)
	}
	if klog.V(0).Enabled() && !klog.V(1).Enabled() {
		return logrus.ErrorLevel
	}
	if klog.V(1).Enabled() && !klog.V(2).Enabled() {
		return logrus.WarnLevel
	}
	if klog.V(2).Enabled() && !klog.V(3).Enabled() {
		return logrus.InfoLevel
	}
	if (klog.V(3).Enabled() || klog.V(4).Enabled() || klog.V(5).Enabled() || klog.V(6).Enabled()) && !klog.V(7).Enabled() {
		return logrus.DebugLevel
	}

	// klog.V(7).Enabled() || klog.V(8).Enabled() || klog.V(9).Enabled()
	return logrus.TraceLevel
}

// verbosityLevel sets VERBOSITY based on LOG_LEVEL
// ERROR, FATAL --> v=0
// WARN --> v=1
// INFO --> v=2
// DEBUG --> v=3:6
// TRACE --> v=7 and above (i.e., show everything)
func logLevelToVerbosityLevel() string {
	switch logrus.GetLevel() {
	case logrus.TraceLevel:
		return "20"
	case logrus.DebugLevel:
		return "6"
	case logrus.InfoLevel:
		return "2"
	case logrus.WarnLevel:
		return "1"
	case logrus.ErrorLevel:
		return "0"
	case logrus.FatalLevel:
		return "0"
	}
	return "2" // return default "2" for info.
}

// CustomLogger is a wrapper around logrus to forward klog messages
type logrusKlog struct {
	logger *logrus.Entry
}

func (l logrusKlog) Init(info logr.RuntimeInfo) {
	l.logger.Logger.SetLevel(logrusLevel())
}

func (l logrusKlog) Enabled(level int) bool {
	l.logger.Trace("loglevel: ", logLevelToVerbosityLevel())
	logLevel, err := strconv.ParseInt(logLevelToVerbosityLevel(), 10, 64)
	if err != nil {
		l.logger.Error("failed to parseInt log level verbosity: ", logLevelToVerbosityLevel())
		return false
	}
	return int64(level) == logLevel
}

func toLogrusFields(keysAndValues ...interface{}) logrus.Fields {
	fields := logrus.Fields{}
	for i := 0; i < len(keysAndValues); i += 2 {
		key := fmt.Sprintf("%v", keysAndValues[i])
		fields[key] = keysAndValues[i+1]
	}
	return fields
}

func (l logrusKlog) Info(level int, msg string, keysAndValues ...any) {
	l.logger.WithFields(toLogrusFields(keysAndValues...)).Info(msg)
}

func (l logrusKlog) Error(err error, msg string, keysAndValues ...any) {
	l.logger.WithFields(toLogrusFields(keysAndValues...)).WithError(err).Error(msg)
}

func (l logrusKlog) WithName(name string) logr.LogSink {
	// do nothing
	return l
}

func (l logrusKlog) WithValues(keysAndValues ...any) logr.LogSink {
	// do nothing
	return l
}

func configureLogging() {
	// set logrus log-level for tigera-apiserver logging
	logrus.SetLevel(logrusLevel())

	// create a logrus logger to be used by klog
	logrusLogger := logrus.New().WithField("klog-logger", "tigera-apiserver")
	logrusLogger.Logger.SetLevel(logrusLevel())

	logrusLoggerWrapper := logrusKlog{logger: logrusLogger}

	klogLogger := logr.New(logrusLoggerWrapper)
	klog.SetLogger(klogLogger)

	// set klog verbosity for libraries used in tigera-apiserver
	msg, err := logs.GlogSetter(logLevelToVerbosityLevel())
	if err != nil {
		logrus.Errorf("Failed to set glog setter: %v", err)
	}
	if err == nil && msg != "" {
		logrus.Tracef("Successfully set glog setter: %s", msg)
	}
}
