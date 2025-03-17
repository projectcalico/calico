package emitter

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/fsnotify/fsnotify"
	"github.com/projectcalico/calico/lib/std/chanutil"
	"github.com/sirupsen/logrus"
)

// Path to the file that controls whether the emitter is enabled.
var emitterEnabledPath = "/var/run/calico/flow_emitter_enabled"

type emitterConfig struct {
	Enabled bool `json:"enabled"`
}

func isEnabled() bool {
	if _, err := os.Stat(emitterEnabledPath); err != nil {
		// If the file doesn't exist, the emitter is disabled.
		return false
	}

	// Open the file and read the contents.
	contents, err := os.ReadFile(emitterEnabledPath)
	if err != nil {
		logrus.WithError(err).Warn("Error reading emitter enabled file")
		return false
	}
	var cfg emitterConfig
	err = json.Unmarshal(contents, &cfg)
	if err != nil {
		logrus.WithError(err).Warn("Error unmarshalling emitter enabled file")
		return false
	}
	return cfg.Enabled
}

type FileEnabler struct {
	onUpdate  chan struct{}
	isEnabled func() bool
	emitter   *Emitter
	watchFn   func()
}

func newFileEnabler(emitter *Emitter) (*FileEnabler, error) {
	onUpdate := make(chan struct{})

	// Watch for changes to the input file.
	watchFn, err := watchFiles(onUpdate, emitterEnabledPath)
	if err != nil {
		return nil, err
	}

	e := FileEnabler{
		onUpdate:  onUpdate,
		isEnabled: isEnabled,
		emitter:   emitter,
		watchFn:   watchFn,
	}
	return &e, nil
}

func (f *FileEnabler) run() {
	// Start the file watch.
	go f.watchFn()

	for {
		select {
		case <-f.onUpdate:
			if f.isEnabled() {
				logrus.Info("Disabling emitter")
				f.emitter.Disable()
			} else {
				logrus.Info("Enabling emitter")
				f.emitter.Enable()
			}
		}
	}
}

func watchFiles(updChan chan struct{}, files ...string) (func(), error) {
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
