/*
Package log provides support for logging to stdout and stderr.

Log entries will be logged in the following format:

	timestamp hostname [pid]: SEVERITY Message
*/
package log

import (
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

func init() {
	log.AddHook(logutils.ContextHook{})
	log.SetFormatter(&logutils.Formatter{Component: "confd"})
}

// SetLevel sets the log level. Valid levels are panic, fatal, error, warn, info and debug.
func SetLevel(level string) {
	lvl, err := log.ParseLevel(level)
	if err != nil {
		log.SetLevel(log.InfoLevel)
		log.WithError(err).WithField("level", level).Warning("Failed to parse log level, defaulting to INFO")
		return
	}
	log.SetLevel(lvl)
}
