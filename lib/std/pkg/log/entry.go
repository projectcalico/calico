package log

import (
	"context"
	"time"
)

type Entry interface {
	Bytes() ([]byte, error)
	Debug(args ...interface{})
	Error(args ...interface{})
	Fatal(args ...interface{})
	Info(args ...interface{})
	Log(level Level, args ...interface{})
	Logf(level Level, format string, args ...interface{})
	Panic(args ...interface{})
	Print(args ...interface{})
	String() (string, error)
	Trace(args ...interface{})
	Warn(args ...interface{})
	Warning(args ...interface{})
	WithContext(ctx context.Context) Entry
	WithError(err error) Entry
	WithField(key string, value interface{}) Entry
	WithFields(fields Fields) Entry
	WithTime(t time.Time) Entry
}
