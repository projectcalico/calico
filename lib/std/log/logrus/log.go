package logrus

import (
	"context"
	"io"
	"os"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/lib/std/log/types"
)

var _ types.Logger = &logger{}

type config struct {
	componentName string
	output        io.Writer
	level         types.Level
}

type logger struct {
	logrus *logrus.Logger
}

func (logger logger) NewEntry() types.Entry {
	return &entry{logrus.NewEntry(logger.logrus)}
}

func New(opts ...Option) types.Logger {
	cfg := config{
		level:  types.InfoLevel,
		output: os.Stdout,
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	return newLogger(cfg)
}

func newLogger(cfg config) types.Logger {
	formatter := &Formatter{Component: cfg.componentName}
	formatter.init()

	lgrs := logrus.New()

	lgrs.SetFormatter(formatter)
	lgrs.SetReportCaller(true)
	lgrs.SetOutput(cfg.output)
	lgrs.SetLevel(logrus.Level(cfg.level))

	return &logger{lgrs}
}

func NewTesting(t *testing.T, opts ...Option) types.Logger {
	cfg := config{
		level:         types.DebugLevel,
		componentName: "testing",
		output:        TestingTWriter{T: t},
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	logrus.SetLevel(logrus.DebugLevel)
	logrus.SetOutput(os.Stdout)
	return newLogger(cfg)
}

// WithField allocates a new entry and adds a field to it.
// Debug, Print, Info, Warn, Error, Fatal or Panic must be then applied to
// this new returned entry.
// If you want multiple fields, use `WithFields`.
func (logger *logger) WithField(key string, value interface{}) types.Entry {
	return &entry{logger.logrus.WithField(key, value)}
}

// Adds a struct of fields to the log entry. All it does is call `WithField` for
// each `Field`.
func (logger *logger) WithFields(fields types.Fields) types.Entry {
	return &entry{logger.logrus.WithFields(logrus.Fields(fields))}
}

// Add an error as single field to the log entry.  All it does is call
// `WithError` for the given `error`.
func (logger *logger) WithError(err error) types.Entry {
	return &entry{logger.logrus.WithError(err)}
}

// Add a context to the log entry.
func (logger *logger) WithContext(ctx context.Context) types.Entry {
	return &entry{logger.logrus.WithContext(ctx)}
}

// Overrides the time of the log entry.
func (logger *logger) WithTime(t time.Time) types.Entry {
	return &entry{logger.logrus.WithTime(t)}
}

func (logger *logger) Logf(level types.Level, format string, args ...interface{}) {
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

func (logger *logger) Log(level types.Level, args ...interface{}) {
	logger.logrus.Log(logrus.Level(level), args...)
}

func (logger *logger) LogFn(level types.Level, fn types.LogFunction) {
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

func (logger *logger) TraceFn(fn types.LogFunction) {
	logger.logrus.TraceFn(logrus.LogFunction(fn))
}

func (logger *logger) DebugFn(fn types.LogFunction) {
	logger.logrus.DebugFn(logrus.LogFunction(fn))
}

func (logger *logger) InfoFn(fn types.LogFunction) {
	logger.logrus.InfoFn(logrus.LogFunction(fn))
}

func (logger *logger) PrintFn(fn types.LogFunction) {
	logger.logrus.PrintFn(logrus.LogFunction(fn))
}

func (logger *logger) WarnFn(fn types.LogFunction) {
	logger.logrus.WarnFn(logrus.LogFunction(fn))
}

func (logger *logger) WarningFn(fn types.LogFunction) {
	logger.logrus.WarningFn(logrus.LogFunction(fn))
}

func (logger *logger) ErrorFn(fn types.LogFunction) {
	logger.logrus.ErrorFn(logrus.LogFunction(fn))
}

func (logger *logger) FatalFn(fn types.LogFunction) {
	logger.logrus.FatalFn(logrus.LogFunction(fn))
}

func (logger *logger) PanicFn(fn types.LogFunction) {
	logger.logrus.PanicFn(logrus.LogFunction(fn))
}

func (logger *logger) Logln(level types.Level, args ...interface{}) {
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
func (logger *logger) SetLevel(level types.Level) {
	logger.logrus.SetLevel(logrus.Level(level))
}

// GetLevel returns the logger level.
func (logger *logger) GetLevel() types.Level {
	return types.Level(logger.logrus.GetLevel())
}

type hookWrapper struct {
	hook types.Hook
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
func (logger *logger) AddHook(hook types.Hook) {
	logger.logrus.AddHook(&hookWrapper{hook})
}

// IsLevelEnabled checks if the log level of the logger is greater than the level param
func (logger *logger) IsLevelEnabled(level types.Level) bool {
	return logger.logrus.IsLevelEnabled(logrus.Level(level))
}

type formatterWrapper struct {
	formatter types.Formatter
}

func (wrapper *formatterWrapper) Format(e *logrus.Entry) ([]byte, error) {
	return wrapper.formatter.Format(&entry{e})
}

// SetFormatter sets the logger formatter.
func (logger *logger) SetFormatter(formatter types.Formatter) {
	logger.logrus.SetFormatter(&formatterWrapper{formatter})
}

// SetOutput sets the logger output.
func (logger *logger) SetOutput(output io.Writer) {
	logger.logrus.SetOutput(output)
}

func (logger *logger) SetReportCaller(reportCaller bool) {
	logger.logrus.SetReportCaller(reportCaller)
}
