// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nodeservices

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/projectcalico/calico/node/pkg/allocateip"
	"github.com/projectcalico/calico/node/pkg/cni"
	"github.com/projectcalico/calico/node/pkg/lifecycle/startup"
	"github.com/projectcalico/calico/node/pkg/status"
)

// Run starts all consolidated node services as goroutines under a shared
// context. If any service returns an error the context is cancelled,
// causing all others to shut down, and the process exits non-zero so
// runit restarts it.
func Run() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		log.WithField("signal", sig).Info("Received signal, shutting down node services")
		cancel()
	}()

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		log.Info("Starting complete-startup service")
		return startup.ManageNodeCondition(ctx, 5*time.Minute)
	})

	g.Go(func() error {
		log.Info("Starting tunnel IP allocator service")
		return allocateip.Run(ctx, false)
	})

	g.Go(func() error {
		log.Info("Starting node status reporter service")
		return status.RunWithContext(ctx)
	})

	if os.Getenv("CALICO_NETWORKING_BACKEND") != "none" {
		g.Go(func() error {
			log.Info("Starting monitor-addresses service")
			return startup.MonitorIPAddressSubnetsWithContext(ctx)
		})
	}

	if os.Getenv("CALICO_MANAGE_CNI") != "false" {
		g.Go(func() error {
			log.Info("Starting CNI token monitor service")
			return cni.RunWithContext(ctx)
		})
	}

	if err := g.Wait(); err != nil {
		log.WithError(err).Fatal("Node services exiting due to error")
	}
	log.Info("Node services shutdown complete")
}
