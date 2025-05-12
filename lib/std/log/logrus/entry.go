package logrus

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/lib/std/log/types"
)

type entry struct {
	entry *logrus.Entry
}

func (e *entry) Dup() types.Entry {
	return &entry{e.entry.Dup()}
}

func (e *entry) Bytes() ([]byte, error) {
	return e.entry.Bytes()
}

func (e *entry) String() (string, error) {
	return e.entry.String()
}

func (e *entry) WithError(err error) types.Entry {
	return &entry{e.entry.WithError(err)}
}

func (e *entry) WithContext(ctx context.Context) types.Entry {
	return &entry{e.entry.WithContext(ctx)}
}

func (e *entry) WithField(key string, value interface{}) types.Entry {
	return &entry{e.entry.WithField(key, value)}
}

func (e *entry) WithFields(fields types.Fields) types.Entry {
	return &entry{e.entry.WithFields(logrus.Fields(fields))}
}

func (e *entry) WithTime(t time.Time) types.Entry {
	return &entry{e.entry.WithTime(t)}
}

func (e entry) HasCaller() (has bool) {
	return e.entry.HasCaller()
}

func (e entry) Log(level types.Level, args ...interface{}) {
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

func (e *entry) Logf(level types.Level, format string, args ...interface{}) {
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

func (e *entry) Logln(level types.Level, args ...interface{}) {
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
