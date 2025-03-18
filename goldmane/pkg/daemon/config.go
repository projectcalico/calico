// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/aggregator"
	"github.com/projectcalico/calico/goldmane/pkg/aggregator/bucketing"
	"github.com/projectcalico/calico/goldmane/pkg/internal/utils"
)

type goldmaneFileConfig struct {
	EmitFlows bool `json:"emitFlows"`
}

type sinkManager struct {
	aggregator *aggregator.LogAggregator
	sink       bucketing.Sink
	upd        chan struct{}
	watchFn    func(context.Context)
	path       string
}

func newSinkManager(agg *aggregator.LogAggregator, sink bucketing.Sink, path string) (*sinkManager, error) {
	onUpdate := make(chan struct{}, 1)

	// Watch for changes to the input file.
	watchFn, err := utils.WatchFilesFn(onUpdate, path)
	if err != nil {
		return nil, err
	}

	if sink == nil {
		return nil, fmt.Errorf("a sink must be provided")
	}
	if agg == nil {
		return nil, fmt.Errorf("an aggregator must be provided")
	}

	e := sinkManager{
		upd:        onUpdate,
		watchFn:    watchFn,
		aggregator: agg,
		sink:       sink,
		path:       path,
	}
	return &e, nil
}

func (f *sinkManager) run(ctx context.Context) {
	logrus.WithField("path", f.path).Info("Starting sink manager with config path")
	defer logrus.Warn("Sink manager exiting")
	defer close(f.upd)

	// Start of day - check if we should enable the sink.
	if sinkEnabled(f.path) {
		logrus.Debug("Sink enabled at startup")
		f.aggregator.SetSink(f.sink)
	}
	logrus.Info("Sink manager started")

	// Start the file watch.
	go f.watchFn(ctx)

	go func() {
		// If enablement changes, update the sink.
		for range f.upd {
			if sinkEnabled(f.path) {
				f.aggregator.SetSink(f.sink)
			} else {
				f.aggregator.SetSink(nil)
			}
		}
	}()

	<-ctx.Done()
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
	return cfg.EmitFlows
}
