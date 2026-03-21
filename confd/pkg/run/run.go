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
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/confd/pkg/backends"
	"github.com/projectcalico/calico/confd/pkg/backends/calico"
	"github.com/projectcalico/calico/confd/pkg/config"
	"github.com/projectcalico/calico/confd/pkg/resource/template"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/winutils"
)

// Run is the entry point for the confd binary. It creates clients from config/environment,
// handles signal setup, and calls os.Exit on completion.
func Run(cfg *config.Config) {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Create clients from config/environment.
	cc, k8sClient, err := createClients(cfg)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create clients")
	}

	if err := RunWithContext(ctx, cfg, cc, k8sClient, nil); err != nil {
		logrus.Fatal(err.Error())
	}
	os.Exit(0)
}

// RunWithContext runs confd using the provided context for lifecycle management.
// If storeClient is nil, a new calico confd client is created using the provided
// Calico and K8s clients. In oneshot mode, it processes templates once and returns.
// In daemon mode, it watches for changes until the context is cancelled.
func RunWithContext(ctx context.Context, cfg *config.Config, cc clientv3.Interface, k8sClient kubernetes.Interface, storeClient backends.StoreClient) error {
	logrus.Info("Starting calico-confd")

	if storeClient == nil {
		var err error
		storeClient, err = calico.NewCalicoClient(cfg, cc, k8sClient)
		if err != nil {
			return fmt.Errorf("creating calico confd client: %w", err)
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
		defer storeClient.Stop()
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

// createClients builds the Calico v3 and Kubernetes clients from config and environment.
func createClients(cfg *config.Config) (clientv3.Interface, kubernetes.Interface, error) {
	clientCfg, err := apiconfig.LoadClientConfig(cfg.CalicoConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("loading calico client config: %w", err)
	}

	cc, err := clientv3.New(*clientCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("creating calico client: %w", err)
	}

	cfgFile := os.Getenv("KUBECONFIG")
	restCfg, err := winutils.BuildConfigFromFlags("", cfgFile)
	if err != nil {
		logrus.WithError(err).Info("KUBECONFIG not found, attempting in-cluster config")
		restCfg, err = winutils.GetInClusterConfig()
		if err != nil {
			return cc, nil, nil
		}
	}

	k8sClient, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		logrus.WithError(err).Warning("Failed to create K8s client")
		return cc, nil, nil
	}

	return cc, k8sClient, nil
}
