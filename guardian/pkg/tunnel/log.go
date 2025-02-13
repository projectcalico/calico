package tunnel

import "github.com/sirupsen/logrus"

type logrusWriter struct {
	log *logrus.Entry
}

func (l *logrusWriter) Write(p []byte) (n int, err error) {
	l.log.Info(string(p))
	return len(p), nil
}
