package log

import (
	"bytes"
	"context"
	"io"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

var _ Logger = &logger{}

type config struct {
	componentName  string
	output         io.Writer
	level          Level
	formatter      Formatter
	hooks          []Hook
	backgroundHook *BackgroundHook
}

type logger struct {
	*logrus.Logger
}

func (logger *logger) StandardLogger() Logger {
	return logger
}

func (logger *logger) RedirectToTestingT(t *testing.T) func() {
	oldOut := logger.GetOutput()
	cancel := func() {
		logger.SetOutput(oldOut)
	}
	logger.SetOutput(TestingTWriter{T: t})
	return cancel
}

func newLogrus(opts ...Option) Logger {
	cfg := config{
		level:  WarnLevel,
		output: os.Stdout,
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	return newLogger(cfg)
}

func newLogger(cfg config) Logger {
	var logrusFormatter logrus.Formatter

	if cfg.formatter != nil {
		logrusFormatter = &formatterAdaptor{cfg.formatter}
	} else {
		formatter := NewDefaultFormatterWithName(cfg.componentName)
		logrusFormatter = &formatterAdaptor{formatter}
	}

	lgrs := logrus.New()
	lgrs.SetReportCaller(true)
	lgrs.SetFormatter(logrusFormatter)
	lgrs.SetOutput(cfg.output)
	lgrs.SetLevel(logrus.Level(cfg.level))
	for _, hook := range cfg.hooks {
		lgrs.AddHook(&hookAdaptor{hook})
	}

	if cfg.backgroundHook != nil {
		lgrs.AddHook(&hookAdaptor{cfg.backgroundHook})
	}

	return &logger{lgrs}
}

func (logger *logger) GetOutput() io.Writer {
	return logger.Logger.Out
}

func (logger *logger) NewEntry() Entry {
	return &entry{logrus.NewEntry(logger.Logger)}
}

// WithField allocates a new entry and adds a field to it.
// Debug, Print, Info, Warn, Error, Fatal or Panic must be then applied to
// this new returned entry.
// If you want multiple fields, use `WithFields`.
func (logger *logger) WithField(key string, value interface{}) Entry {
	return &entry{logger.Logger.WithField(key, value)}
}

// Adds a struct of fields to the log entry. All it does is call `WithField` for
// each `Field`.
func (logger *logger) WithFields(fields Fields) Entry {
	return &entry{logger.Logger.WithFields(logrus.Fields(fields))}
}

// Add an error as single field to the log entry.  All it does is call
// `WithError` for the given `error`.
func (logger *logger) WithError(err error) Entry {
	return &entry{logger.Logger.WithError(err)}
}

// Add a context to the log entry.
func (logger *logger) WithContext(ctx context.Context) Entry {
	return &entry{logger.Logger.WithContext(ctx)}
}

// Overrides the time of the log entry.
func (logger *logger) WithTime(t time.Time) Entry {
	return &entry{logger.Logger.WithTime(t)}
}

func (logger *logger) Logf(level Level, format string, args ...interface{}) {
	logger.Logger.Logf(logrus.Level(level), format, args...)
}

func (logger *logger) Tracef(format string, args ...interface{}) {
	logger.Logger.Tracef(format, args...)
}

func (logger *logger) Debugf(format string, args ...interface{}) {
	logger.Logger.Debugf(format, args...)
}

func (logger *logger) Infof(format string, args ...interface{}) {
	logger.Logger.Infof(format, args...)
}

func (logger *logger) Printf(format string, args ...interface{}) {
	logger.Logger.Printf(format, args...)
}

func (logger *logger) Warnf(format string, args ...interface{}) {
	logger.Logger.Warnf(format, args...)
}

func (logger *logger) Warningf(format string, args ...interface{}) {
	logger.Logger.Warningf(format, args...)
}

func (logger *logger) Errorf(format string, args ...interface{}) {
	logger.Logger.Errorf(format, args...)
}

func (logger *logger) Fatalf(format string, args ...interface{}) {
	logger.Logger.Fatalf(format, args...)
}

func (logger *logger) Panicf(format string, args ...interface{}) {
	logger.Logger.Panicf(format, args...)
}

func (logger *logger) Log(level Level, args ...interface{}) {
	logger.Logger.Log(logrus.Level(level), args...)
}

func (logger *logger) LogFn(level Level, fn LogFunction) {
	logger.Logger.LogFn(logrus.Level(level), logrus.LogFunction(fn))
}

func (logger *logger) Trace(args ...interface{}) {
	logger.Logger.Trace(args...)
}

func (logger *logger) Debug(args ...interface{}) {
	logger.Logger.Debug(args...)
}

func (logger *logger) Info(args ...interface{}) {
	logger.Logger.Info(args...)
}

func (logger *logger) Print(args ...interface{}) {
	logger.Logger.Print(args...)
}

func (logger *logger) Warn(args ...interface{}) {
	logger.Logger.Warn(args...)
}

func (logger *logger) Warning(args ...interface{}) {
	logger.Logger.Warning(args...)
}

func (logger *logger) Error(args ...interface{}) {
	logger.Logger.Error(args...)
}

func (logger *logger) Fatal(args ...interface{}) {
	logger.Logger.Fatal(args...)
}

func (logger *logger) Panic(args ...interface{}) {
	logger.Logger.Panic(args...)
}

func (logger *logger) TraceFn(fn LogFunction) {
	logger.Logger.TraceFn(logrus.LogFunction(fn))
}

func (logger *logger) DebugFn(fn LogFunction) {
	logger.Logger.DebugFn(logrus.LogFunction(fn))
}

func (logger *logger) InfoFn(fn LogFunction) {
	logger.Logger.InfoFn(logrus.LogFunction(fn))
}

func (logger *logger) PrintFn(fn LogFunction) {
	logger.Logger.PrintFn(logrus.LogFunction(fn))
}

func (logger *logger) WarnFn(fn LogFunction) {
	logger.Logger.WarnFn(logrus.LogFunction(fn))
}

func (logger *logger) WarningFn(fn LogFunction) {
	logger.Logger.WarningFn(logrus.LogFunction(fn))
}

func (logger *logger) ErrorFn(fn LogFunction) {
	logger.Logger.ErrorFn(logrus.LogFunction(fn))
}

func (logger *logger) FatalFn(fn LogFunction) {
	logger.Logger.FatalFn(logrus.LogFunction(fn))
}

func (logger *logger) PanicFn(fn LogFunction) {
	logger.Logger.PanicFn(logrus.LogFunction(fn))
}

func (logger *logger) Logln(level Level, args ...interface{}) {
	logger.Logger.Logln(logrus.Level(level), args...)
}

func (logger *logger) Traceln(args ...interface{}) {
	logger.Logger.Traceln(args...)
}

func (logger *logger) Debugln(args ...interface{}) {
	logger.Logger.Debugln(args...)
}

func (logger *logger) Infoln(args ...interface{}) {
	logger.Logger.Infoln(args...)
}

func (logger *logger) Println(args ...interface{}) {
	logger.Logger.Println(args...)
}

func (logger *logger) Warnln(args ...interface{}) {
	logger.Logger.Warnln(args...)
}

func (logger *logger) Warningln(args ...interface{}) {
	logger.Logger.Warningln(args...)
}

func (logger *logger) Errorln(args ...interface{}) {
	logger.Logger.Errorln(args...)
}

func (logger *logger) Fatalln(args ...interface{}) {
	logger.Logger.Fatalln(args...)
}

func (logger *logger) Panicln(args ...interface{}) {
	logger.Logger.Panicln(args...)
}

func (logger *logger) Exit(code int) {
	logger.Logger.Exit(code)
}

// SetLevel sets the logger level.
func (logger *logger) SetLevel(level Level) {
	logger.Logger.SetLevel(logrus.Level(level))
}

// GetLevel returns the logger level.
func (logger *logger) GetLevel() Level {
	return Level(logger.Logger.GetLevel())
}

// AddHook adds a hook to the logger hooks.
func (logger *logger) AddHook(hook Hook) {
	logger.Logger.AddHook(&hookAdaptor{hook})
}

// IsLevelEnabled checks if the log level of the logger is greater than the level param
func (logger *logger) IsLevelEnabled(level Level) bool {
	return logger.Logger.IsLevelEnabled(logrus.Level(level))
}

type logrusWrapper struct {
	logrus.Formatter
}

func (l *logrusWrapper) Format(e Entry) ([]byte, error) {
	return l.Formatter.Format(e.(*entry).entry)
}

func NewTextFormatter() Formatter {
	return &logrusWrapper{&logrus.TextFormatter{}}
}

type formatterAdaptor struct {
	Formatter
}

func (adaptor *formatterAdaptor) Format(lgrEntry *logrus.Entry) ([]byte, error) {
	return adaptor.Formatter.Format(&entry{lgrEntry})
}

func (logger *logger) GetFormatter() Formatter {
	if logger.Logger.Formatter != nil {
		switch logger.Logger.Formatter.(type) {
		case *formatterAdaptor:
			return logger.Logger.Formatter.(*formatterAdaptor).Formatter
		default:
			return &logrusWrapper{logger.Logger.Formatter}
		}
	}
	return nil
}

// SetFormatter sets the logger formatter.
func (logger *logger) SetFormatter(formatter Formatter) {
	switch o := formatter.(type) {
	case *logrusWrapper:
		logger.Logger.SetFormatter(o.Formatter)
		return
	default:
		logger.Logger.SetFormatter(&formatterAdaptor{formatter})
	}
}

// SetOutput sets the logger output.
func (logger *logger) SetOutput(output io.Writer) {
	logger.Logger.SetOutput(output)
}

func (logger *logger) SetReportCaller(reportCaller bool) {
	logger.Logger.SetReportCaller(reportCaller)
}

type entry struct {
	entry *logrus.Entry
}

func (e *entry) caller() *runtime.Frame {
	return e.entry.Caller
}

func (e *entry) buffer() *bytes.Buffer {
	return e.entry.Buffer
}

func (e *entry) message() string {
	return e.entry.Message
}

func (e *entry) IsLevelEnabled(level Level) bool {
	return e.entry.Logger.IsLevelEnabled(logrus.Level(level))
}

func (e *entry) SetLevel(level Level) {
	e.entry.Logger.SetLevel(logrus.Level(level))
}

func (e *entry) GetTime() time.Time {
	return e.entry.Time
}

func (e *entry) GetLevel() Level {
	return Level(e.entry.Level)
}

func (e *entry) Logger() Logger {
	return &logger{e.entry.Logger}
}

func (e *entry) Dup() Entry {
	return &entry{e.entry.Dup()}
}

func (e *entry) Bytes() ([]byte, error) {
	return e.entry.Bytes()
}

func (e *entry) String() (string, error) {
	return e.entry.String()
}

func (e *entry) WithError(err error) Entry {
	return &entry{e.entry.WithError(err)}
}

func (e *entry) WithContext(ctx context.Context) Entry {
	return &entry{e.entry.WithContext(ctx)}
}

func (e *entry) WithField(key string, value interface{}) Entry {
	return &entry{e.entry.WithField(key, value)}
}

func (e *entry) SetField(key string, value interface{}) {
	e.entry.Data[key] = value
}

func (e *entry) WithFields(fields Fields) Entry {
	return &entry{e.entry.WithFields(logrus.Fields(fields))}
}

func (e *entry) WithTime(t time.Time) Entry {
	return &entry{e.entry.WithTime(t)}
}

func (e *entry) Log(level Level, args ...interface{}) {
	e.entry.Log(logrus.Level(level), args...)
}

func (e *entry) Trace(args ...interface{}) {
	e.entry.Trace(args...)
}

func (e *entry) Debug(args ...interface{}) {
	e.entry.Debug(args...)
}

func (e *entry) Print(args ...interface{}) {
	e.entry.Print(args...)
}

func (e *entry) Info(args ...interface{}) {
	e.entry.Info(args...)
}

func (e *entry) Warn(args ...interface{}) {
	e.entry.Warn(args...)
}

func (e *entry) Warning(args ...interface{}) {
	e.entry.Warning(args...)
}

func (e *entry) Error(args ...interface{}) {
	e.entry.Error(args...)
}

func (e *entry) Fatal(args ...interface{}) {
	e.entry.Fatal(args...)
}

func (e *entry) Panic(args ...interface{}) {
	e.entry.Panic(args...)
}

func (e *entry) Logf(level Level, format string, args ...interface{}) {
	e.entry.Logf(logrus.Level(level), format, args...)
}

func (e *entry) Tracef(format string, args ...interface{}) {
	e.entry.Tracef(format, args...)
}

func (e *entry) Debugf(format string, args ...interface{}) {
	e.entry.Debugf(format, args...)
}

func (e *entry) Infof(format string, args ...interface{}) {
	e.entry.Infof(format, args...)
}

func (e *entry) Printf(format string, args ...interface{}) {
	e.entry.Printf(format, args...)
}

func (e *entry) Warnf(format string, args ...interface{}) {
	e.entry.Warnf(format, args...)
}

func (e *entry) Warningf(format string, args ...interface{}) {
	e.entry.Warningf(format, args...)
}

func (e *entry) Errorf(format string, args ...interface{}) {
	e.entry.Errorf(format, args...)
}

func (e *entry) Fatalf(format string, args ...interface{}) {
	e.entry.Fatalf(format, args...)
}

func (e *entry) Panicf(format string, args ...interface{}) {
	e.entry.Panicf(format, args...)
}

func (e *entry) Logln(level Level, args ...interface{}) {
	e.entry.Logln(logrus.Level(level), args...)
}

func (e *entry) Traceln(args ...interface{}) {
	e.entry.Traceln(args...)
}

func (e *entry) Debugln(args ...interface{}) {
	e.entry.Debugln(args...)
}

func (e *entry) Infoln(args ...interface{}) {
	e.entry.Infoln(args...)
}

func (e *entry) Println(args ...interface{}) {
	e.entry.Println(args...)
}

func (e *entry) Warnln(args ...interface{}) {
	e.entry.Warnln(args...)
}

func (e *entry) Warningln(args ...interface{}) {
	e.entry.Warningln(args...)
}

func (e *entry) Errorln(args ...interface{}) {
	e.entry.Errorln(args...)
}

func (e *entry) Fatalln(args ...interface{}) {
	e.entry.Fatalln(args...)
}

func (e *entry) Panicln(args ...interface{}) {
	e.entry.Panicln(args...)
}

func (e *entry) Fields() Fields {
	return Fields(e.entry.Data)
}
