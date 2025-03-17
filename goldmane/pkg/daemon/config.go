package daemon

import (
	"encoding/json"
	"os"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/aggregator"
	"github.com/projectcalico/calico/goldmane/pkg/internal/utils"
)

type goldmaneFileConfig struct {
	Enabled bool `json:"enabled"`
}

type sinkManager struct {
	aggregator *aggregator.LogAggregator
	sink       aggregator.Sink
	upd        chan struct{}
	watchFn    func()
	path       string
}

func newSinkManager(agg *aggregator.LogAggregator, sink aggregator.Sink, path string) (*sinkManager, error) {
	onUpdate := make(chan struct{})

	// Watch for changes to the input file.
	watchFn, err := utils.WatchFilesFn(onUpdate, path)
	if err != nil {
		return nil, err
	}

	e := sinkManager{
		upd:        onUpdate,
		watchFn:    watchFn,
		aggregator: agg,
	}
	return &e, nil
}

func (f *sinkManager) run() {
	// Start the file watch.
	go f.watchFn()

	for {
		select {
		case <-f.upd:
			if sinkEnabled(f.path) {
				f.aggregator.SetSink(f.sink)
			} else {
				f.aggregator.SetSink(nil)
			}
		}
	}
}

func sinkEnabled(path string) bool {
	if _, err := os.Stat(path); err != nil {
		// If the file doesn't exist, the emitter is disabled.
		return false
	}

	// Open the file and read the contents.
	contents, err := os.ReadFile(path)
	if err != nil {
		logrus.WithError(err).Warn("Error reading emitter enabled file")
		return false
	}
	var cfg goldmaneFileConfig
	err = json.Unmarshal(contents, &cfg)
	if err != nil {
		logrus.WithError(err).Warn("Error unmarshalling emitter enabled file")
		return false
	}
	return cfg.Enabled
}
