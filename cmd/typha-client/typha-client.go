// Copyright (c) 2017-2018 Tigera, Inc. All rights reserved.
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

package main

import (
	"time"

	log "github.com/sirupsen/logrus"

	"math/rand"
	"runtime"

	"github.com/docopt/docopt-go"

	"context"

	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/typha/pkg/buildinfo"
	"github.com/projectcalico/typha/pkg/config"
	"github.com/projectcalico/typha/pkg/logutils"
	"github.com/projectcalico/typha/pkg/syncclient"
	"github.com/projectcalico/typha/pkg/syncproto"
)

const usage = `Test client for Typha, Calico's fan-out proxy.

Usage:
  typha-client [options]

Options:
  --version                    Print the version and exit.
  --server=<ADDR>              Set the server to connect to [default: localhost:5473].
  --type=<TYPE>                Use a particular syncer type.
`

type syncerCallbacks struct {
	updateCount int
}

func (s *syncerCallbacks) OnStatusUpdated(status api.SyncStatus) {
	log.WithField("status", status).Info("Status received")
}

func (s *syncerCallbacks) OnUpdates(updates []api.Update) {
	s.updateCount += len(updates)
	log.WithField("numUpdates", len(updates)).WithField("total", s.updateCount).Info("Updates received")
}

func main() {
	// Go's RNG is not seeded by default.  Do that now.
	rand.Seed(time.Now().UTC().UnixNano())

	// Set up logging.
	logutils.ConfigureEarlyLogging()
	logutils.ConfigureLogging(&config.Config{
		LogSeverityScreen:       "info",
		DebugDisableLogDropping: true,
	})

	// Parse command-line args.
	version := "Version:            " + buildinfo.GitVersion + "\n" +
		"Full git commit ID: " + buildinfo.GitRevision + "\n" +
		"Build date:         " + buildinfo.BuildDate + "\n"
	arguments, err := docopt.Parse(usage, nil, true, version, false)
	if err != nil {
		println(usage)
		log.Fatalf("Failed to parse usage, exiting: %v", err)
	}
	buildInfoLogCxt := log.WithFields(log.Fields{
		"version":    buildinfo.GitVersion,
		"buildDate":  buildinfo.BuildDate,
		"gitCommit":  buildinfo.GitRevision,
		"GOMAXPROCS": runtime.GOMAXPROCS(0),
	})
	buildInfoLogCxt.Info("Typha starting up")
	log.Infof("Command line arguments: %v", arguments)

	callbacks := &syncerCallbacks{}
	addr := arguments["--server"].(string)
	var syncerType syncproto.SyncerType
	if t, ok := arguments["--type"].(string); ok {
		syncerType = syncproto.SyncerType(t)
	}
	options := &syncclient.Options{
		SyncerType: syncerType,
	}
	client := syncclient.New(addr, buildinfo.GitVersion, "test-host", "some info", callbacks, options)
	err = client.Start(context.Background())
	if err != nil {
		log.WithError(err).Panic("Client failed")
	}
	client.Finished.Wait()
	log.Panic("Client failed")
}
