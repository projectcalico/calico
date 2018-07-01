/*
Package log provides support for logging to stdout and stderr.

Log entries will be logged in the following format:

    timestamp hostname tag[pid]: SEVERITY Message
*/
package log

import (
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/libcalico-go/lib/logutils"
)

// tag represents the application name generating the log message. The tag
// string will appear in all log entires.
var tag string

func init() {
	tag = os.Args[0]
	log.AddHook(logutils.ContextHook{})
	log.SetFormatter(&logutils.Formatter{})
}

// SetTag sets the tag.
func SetTag(t string) {
	tag = t
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
