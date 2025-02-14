package logrus

import (
	"context"
	"io"
	"time"

	"github.com/projectcalico/calico/lib/std/pkg/log"
	"github.com/sirupsen/logrus"
)

func init() {
	log.SetStandardLogger(&logger{logrus.StandardLogger()})
}

var _ log.Logger = &logger{}

type logger struct {
	logrus *logrus.Logger
}

// WithField allocates a new entry and adds a field to it.
// Debug, Print, Info, Warn, Error, Fatal or Panic must be then applied to
// this new returned entry.
// If you want multiple fields, use `WithFields`.
func (logger *logger) WithField(key string, value interface{}) log.Entry {
	return &entry{logger.logrus.WithField(key, value)}
}

// Adds a struct of fields to the log entry. All it does is call `WithField` for
// each `Field`.
func (logger *logger) WithFields(fields log.Fields) log.Entry {
	return &entry{logger.logrus.WithFields(logrus.Fields(fields))}
}

// Add an error as single field to the log entry.  All it does is call
// `WithError` for the given `error`.
func (logger *logger) WithError(err error) log.Entry {
	return &entry{logger.logrus.WithError(err)}
}

// Add a context to the log entry.
func (logger *logger) WithContext(ctx context.Context) log.Entry {
	return &entry{logger.logrus.WithContext(ctx)}
}

// Overrides the time of the log entry.
func (logger *logger) WithTime(t time.Time) log.Entry {
	return &entry{logger.logrus.WithTime(t)}
}

func (logger *logger) Logf(level log.Level, format string, args ...interface{}) {
	logger.logrus.Logf(logrus.Level(level), format, args...)
}

func (logger *logger) Tracef(format string, args ...interface{}) {
	logger.logrus.Tracef(format, args...)
}

func (logger *logger) Debugf(format string, args ...interface{}) {
	logger.logrus.Debugf(format, args...)
}

func (logger *logger) Infof(format string, args ...interface{}) {
	logger.logrus.Infof(format, args...)
}

func (logger *logger) Printf(format string, args ...interface{}) {
	logger.logrus.Printf(format, args...)
}

func (logger *logger) Warnf(format string, args ...interface{}) {
	logger.logrus.Warnf(format, args...)
}

func (logger *logger) Warningf(format string, args ...interface{}) {
	logger.logrus.Warningf(format, args...)
}

func (logger *logger) Errorf(format string, args ...interface{}) {
	logger.logrus.Errorf(format, args...)
}

func (logger *logger) Fatalf(format string, args ...interface{}) {
	logger.logrus.Fatalf(format, args...)
}

func (logger *logger) Panicf(format string, args ...interface{}) {
	logger.logrus.Panicf(format, args...)
}

func (logger *logger) Log(level log.Level, args ...interface{}) {
	logger.logrus.Log(logrus.Level(level), args...)
}

func (logger *logger) LogFn(level log.Level, fn log.LogFunction) {
	logger.logrus.LogFn(logrus.Level(level), logrus.LogFunction(fn))
}

func (logger *logger) Trace(args ...interface{}) {
	logger.logrus.Trace(args...)
}

func (logger *logger) Debug(args ...interface{}) {
	logger.logrus.Debug(args...)
}

func (logger *logger) Info(args ...interface{}) {
	logger.logrus.Info(args...)
}

func (logger *logger) Print(args ...interface{}) {
	logger.logrus.Print(args...)
}

func (logger *logger) Warn(args ...interface{}) {
	logger.logrus.Warn(args...)
}

func (logger *logger) Warning(args ...interface{}) {
	logger.logrus.Warning(args...)
}

func (logger *logger) Error(args ...interface{}) {
	logger.logrus.Error(args...)
}

func (logger *logger) Fatal(args ...interface{}) {
	logger.logrus.Fatal(args...)
}

func (logger *logger) Panic(args ...interface{}) {
	logger.logrus.Panic(args...)
}

func (logger *logger) TraceFn(fn log.LogFunction) {
	logger.logrus.TraceFn(logrus.LogFunction(fn))
}

func (logger *logger) DebugFn(fn log.LogFunction) {
	logger.logrus.DebugFn(logrus.LogFunction(fn))
}

func (logger *logger) InfoFn(fn log.LogFunction) {
	logger.logrus.InfoFn(logrus.LogFunction(fn))
}

func (logger *logger) PrintFn(fn log.LogFunction) {
	logger.logrus.PrintFn(logrus.LogFunction(fn))
}

func (logger *logger) WarnFn(fn log.LogFunction) {
	logger.logrus.WarnFn(logrus.LogFunction(fn))
}

func (logger *logger) WarningFn(fn log.LogFunction) {
	logger.logrus.WarningFn(logrus.LogFunction(fn))
}

func (logger *logger) ErrorFn(fn log.LogFunction) {
	logger.logrus.ErrorFn(logrus.LogFunction(fn))
}

func (logger *logger) FatalFn(fn log.LogFunction) {
	logger.logrus.FatalFn(logrus.LogFunction(fn))
}

func (logger *logger) PanicFn(fn log.LogFunction) {
	logger.logrus.PanicFn(logrus.LogFunction(fn))
}

func (logger *logger) Logln(level log.Level, args ...interface{}) {
	logger.logrus.Logln(logrus.Level(level), args...)
}

func (logger *logger) Traceln(args ...interface{}) {
	logger.logrus.Traceln(args...)
}

func (logger *logger) Debugln(args ...interface{}) {
	logger.logrus.Debugln(args...)
}

func (logger *logger) Infoln(args ...interface{}) {
	logger.logrus.Infoln(args...)
}

func (logger *logger) Println(args ...interface{}) {
	logger.logrus.Println(args...)
}

func (logger *logger) Warnln(args ...interface{}) {
	logger.logrus.Warnln(args...)
}

func (logger *logger) Warningln(args ...interface{}) {
	logger.logrus.Warningln(args...)
}

func (logger *logger) Errorln(args ...interface{}) {
	logger.logrus.Errorln(args...)
}

func (logger *logger) Fatalln(args ...interface{}) {
	logger.logrus.Fatalln(args...)
}

func (logger *logger) Panicln(args ...interface{}) {
	logger.logrus.Panicln(args...)
}

func (logger *logger) Exit(code int) {
	logger.logrus.Exit(code)
}

// SetLevel sets the logger level.
func (logger *logger) SetLevel(level log.Level) {
	logger.logrus.SetLevel(logrus.Level(level))
}

// GetLevel returns the logger level.
func (logger *logger) GetLevel() log.Level {
	return log.Level(logger.logrus.GetLevel())
}

type hookWrapper struct {
	hook log.Hook
}

func (h *hookWrapper) Levels() []logrus.Level {
	var levels []logrus.Level
	for _, level := range h.hook.Levels() {
		levels = append(levels, logrus.Level(level))
	}
	return levels
}

func (h *hookWrapper) Fire(e *logrus.Entry) error {
	return h.hook.Fire(&entry{e})
}

// AddHook adds a hook to the logger hooks.
func (logger *logger) AddHook(hook log.Hook) {
	logger.logrus.AddHook(&hookWrapper{hook})
}

// IsLevelEnabled checks if the log level of the logger is greater than the level param
func (logger *logger) IsLevelEnabled(level log.Level) bool {
	return logger.logrus.IsLevelEnabled(logrus.Level(level))
}

type formatterWrapper struct {
	formatter log.Formatter
}

func (wrapper *formatterWrapper) Format(e *logrus.Entry) ([]byte, error) {
	return wrapper.formatter.Format(&entry{e})
}

// SetFormatter sets the logger formatter.
func (logger *logger) SetFormatter(formatter log.Formatter) {
	logger.logrus.SetFormatter(&formatterWrapper{formatter})
}

// SetOutput sets the logger output.
func (logger *logger) SetOutput(output io.Writer) {
	logger.logrus.SetOutput(output)
}

func (logger *logger) SetReportCaller(reportCaller bool) {
	logger.logrus.SetReportCaller(reportCaller)
}
