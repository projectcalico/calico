// Copyright (c) 2017-2026 Tigera, Inc. All rights reserved.
//
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

package run

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	logrus "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/confd/pkg/backends"
	"github.com/projectcalico/calico/confd/pkg/backends/calico"
	"github.com/projectcalico/calico/confd/pkg/config"
	"github.com/projectcalico/calico/confd/pkg/resource/template"
)

// Run is the original entry point for the confd binary. It handles signal
// setup and calls os.Exit on completion. New callers should use RunWithContext.
func Run(cfg *config.Config) {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := RunWithContext(ctx, cfg, nil); err != nil {
		logrus.Fatal(err.Error())
	}
	os.Exit(0)
}

// RunWithContext runs confd using the provided context for lifecycle management.
// If storeClient is nil, a new calico client is created from the config.
// In oneshot mode, it processes templates once and returns.
// In daemon mode, it watches for changes until the context is cancelled.
func RunWithContext(ctx context.Context, cfg *config.Config, storeClient backends.StoreClient) error {
	logrus.Info("Starting calico-confd")

	if storeClient == nil {
		var err error
		storeClient, err = calico.NewCalicoClient(cfg)
		if err != nil {
			return fmt.Errorf("creating calico client: %w", err)
		}
	}

	templateConfig := template.Config{
		ConfDir:       cfg.ConfDir,
		ConfigDir:     filepath.Join(cfg.ConfDir, "conf.d"),
		KeepStageFile: cfg.KeepStageFile,
		Noop:          cfg.Noop,
		Prefix:        cfg.Prefix,
		SyncOnly:      cfg.SyncOnly,
		TemplateDir:   filepath.Join(cfg.ConfDir, "templates"),
		StoreClient:   storeClient,
	}

	if cfg.Onetime {
		if err := template.Process(templateConfig); err != nil {
			return fmt.Errorf("processing templates: %w", err)
		}
		return nil
	}

	stopChan := make(chan bool)
	doneChan := make(chan bool)
	errChan := make(chan error, 10)

	processor := template.WatchProcessor(templateConfig, stopChan, doneChan, errChan)
	go processor.Process()

	for {
		select {
		case err := <-errChan:
			logrus.WithError(err).Error("Template processing error")
		case <-doneChan:
			return nil
		case <-ctx.Done():
			logrus.Info("Context cancelled, shutting down")
			close(doneChan)
			return nil
		}
	}
}
