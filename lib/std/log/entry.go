package log

import (
	"context"
	"time"
)

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
