package types

import (
	"context"
	"io"
	"testing"
	"time"
)

type Level uint32

const (
	// PanicLevel level, highest level of severity. Logs and then calls panic with the
	// message passed to Debug, Info, ...
	PanicLevel Level = iota
	// FatalLevel level. Logs and then calls `logger.Exit(1)`. It will exit even if the
	// logging level is set to Panic.
	FatalLevel
	// ErrorLevel level. Logs. Used for errors that should definitely be noted.
	// Commonly used for hooks to send errors to an error tracking service.
	ErrorLevel
	// WarnLevel level. Non-critical entries that deserve eyes.
	WarnLevel
	// InfoLevel level. General operational entries about what's going on inside the
	// application.
	InfoLevel
	// DebugLevel level. Usually only enabled when debugging. Very verbose logging.
	DebugLevel
	// TraceLevel level. Designates finer-grained informational events than the Debug.
	TraceLevel
)

type Hook interface {
	Levels() []Level
	Fire(Entry) error
}

// Fields type, used to pass to `WithFields`.
type Fields map[string]interface{}

// LogFunction For big messages, it can be more efficient to pass a function
// and only call it if the log level is actually enables rather than
// generating the log message and then checking if the level is enabled
type LogFunction func() []interface{}

type Formatter interface {
	Format(Entry) ([]byte, error)
}

type Logger interface {
	GetLevel() Level
	IsLevelEnabled(level Level) bool
	SetReportCaller(reportCaller bool)
	AddHook(hook Hook)
	SetLevel(level Level)
	SetFormatter(formatter Formatter)
	GetOutput() io.Writer
	SetOutput(output io.Writer)
	WithField(key string, value interface{}) Entry
	WithFields(fields Fields) Entry
	WithError(err error) Entry
	WithContext(ctx context.Context) Entry
	WithTime(t time.Time) Entry
	Logf(level Level, format string, args ...interface{})
	Tracef(format string, args ...interface{})
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Printf(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Warningf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Fatalf(format string, args ...interface{})
	Panicf(format string, args ...interface{})
	Log(level Level, args ...interface{})
	LogFn(level Level, fn LogFunction)
	Trace(args ...interface{})
	Debug(args ...interface{})
	Info(args ...interface{})
	Print(args ...interface{})
	Warn(args ...interface{})
	Warning(args ...interface{})
	Error(args ...interface{})
	Fatal(args ...interface{})
	Panic(args ...interface{})
	TraceFn(fn LogFunction)
	DebugFn(fn LogFunction)
	InfoFn(fn LogFunction)
	PrintFn(fn LogFunction)
	WarnFn(fn LogFunction)
	WarningFn(fn LogFunction)
	ErrorFn(fn LogFunction)
	FatalFn(fn LogFunction)
	PanicFn(fn LogFunction)
	Logln(level Level, args ...interface{})
	Traceln(args ...interface{})
	Debugln(args ...interface{})
	Println(args ...interface{})
	Infoln(args ...interface{})
	Warnln(args ...interface{})
	Warningln(args ...interface{})
	Errorln(args ...interface{})
	Panicln(args ...interface{})
	Fatalln(args ...interface{})
	NewEntry() Entry
	RedirectToTestingT(t *testing.T) func()
}

type Entry interface {
	Bytes() ([]byte, error)
	Debug(args ...interface{})
	Debugf(format string, args ...interface{})
	Error(args ...interface{})
	Errorf(format string, args ...interface{})
	Fatal(args ...interface{})
	Fatalf(format string, args ...interface{})
	Info(args ...interface{})
	Infof(format string, args ...interface{})
	Log(level Level, args ...interface{})
	Logf(level Level, format string, args ...interface{})
	Panic(args ...interface{})
	Panicf(format string, args ...interface{})
	Print(args ...interface{})
	String() (string, error)
	Trace(args ...interface{})
	Warn(args ...interface{})
	Warnf(format string, args ...interface{})
	Warning(args ...interface{})
	Warningf(format string, args ...interface{})
	WithContext(ctx context.Context) Entry
	WithError(err error) Entry
	WithField(key string, value interface{}) Entry
	WithFields(fields Fields) Entry
	WithTime(t time.Time) Entry
}
