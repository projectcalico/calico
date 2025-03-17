package utils

import (
	"fmt"

	"github.com/fsnotify/fsnotify"
	"github.com/projectcalico/calico/lib/std/chanutil"
	"github.com/sirupsen/logrus"
)

// WatchFiles monitors the given files and sends an update to the given channel when any of the files change.
func WatchFiles(updChan chan struct{}, files ...string) (func(), error) {
	fileWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("error creating file watcher: %s", err)
	}
	for _, file := range files {
		if err := fileWatcher.Add(file); err != nil {
			logrus.WithError(err).Warn("Error watching file for changes")
			continue
		}
		logrus.WithField("file", file).Debug("Watching file for changes")
	}

	return func() {
		// If we exit this function, make sure to close the file watcher and update channel.
		defer fileWatcher.Close()
		defer close(updChan)
		defer logrus.Info("File watcher closed")
		for {
			select {
			case event, ok := <-fileWatcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write {
					logrus.WithField("file", event.Name).Info("File changed, triggering update")
					_ = chanutil.WriteNonBlocking(updChan, struct{}{})
				}
			case err, ok := <-fileWatcher.Errors:
				if !ok {
					return
				}
				logrus.Errorf("error watching file: %s", err)
			}
		}
	}, nil
}
