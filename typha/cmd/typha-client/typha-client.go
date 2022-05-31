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
	"context"
	"os"
	"runtime"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/seedrng"

	"github.com/docopt/docopt-go"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/typha/pkg/buildinfo"
	"github.com/projectcalico/calico/typha/pkg/config"
	"github.com/projectcalico/calico/typha/pkg/discovery"
	"github.com/projectcalico/calico/typha/pkg/logutils"
	"github.com/projectcalico/calico/typha/pkg/syncclient"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
)

const usage = `Test client for Typha, Calico's fan-out proxy.

Usage:
  typha-client [options]

Options:
  --version                    Print the version and exit.
  --server=<ADDR>              Set the server to connect to [default: localhost:5473].
  --type=<TYPE>                Use a particular syncer type.
  --key-file=<FILE>            TLS: private key file.  Used to authenticate to the server.
  --cert-file=<FILE>           TLS: certificate file.  Used to authenticate to the server.
                               Must be signed by the CA that the server accepts.
  --ca-file=<FILE>             TLS: CA certificate file.  Used to authenticate the server's certificate.
  --server-cn=<NAME>           TLS: expected server common name.  Used to authenticate the server's certificate.
  --server-uri=<URI>           TLS: expected server URI SAN.  Used to authenticate the server's certificate.

`

type syncerCallbacks struct {
	updateCount int
	lastLogTime time.Time
}

func (s *syncerCallbacks) OnStatusUpdated(status api.SyncStatus) {
	log.WithField("status", status).Info("Status received")
}

func (s *syncerCallbacks) OnUpdates(updates []api.Update) {
	s.updateCount += len(updates)
	if time.Since(s.lastLogTime) < time.Second {
		return
	}
	log.WithField("numUpdates", len(updates)).WithField("total", s.updateCount).Info("Updates received")
	s.lastLogTime = time.Now()
}

func main() {
	// Go's RNG is not seeded by default.  Do that now.
	seedrng.EnsureSeeded()

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
	p := &docopt.Parser{OptionsFirst: false, SkipHelpFlags: false}
	arguments, err := p.ParseArgs(usage, nil, version)
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
	buildInfoLogCxt.Info("Typha client starting up")
	log.Infof("Command line arguments: %v", arguments)

	callbacks := &syncerCallbacks{}
	addr := arguments["--server"].(string)
	var syncerType syncproto.SyncerType
	if t, ok := arguments["--type"].(string); ok {
		syncerType = syncproto.SyncerType(t)
	}
	options := &syncclient.Options{
		SyncerType:   syncerType,
		KeyFile:      arguments["--key-file"].(string),
		CertFile:     arguments["--cert-file"].(string),
		CAFile:       arguments["--ca-file"].(string),
		ServerCN:     arguments["--server-cn"].(string),
		ServerURISAN: arguments["--server-uri"].(string),
	}

	hostname, _ := os.Hostname()
	client := syncclient.New([]discovery.Typha{{Addr: addr}}, buildinfo.GitVersion, hostname, "typha command-line client", callbacks, options)
	err = client.Start(context.Background())
	if err != nil {
		log.WithError(err).Panic("Client failed")
	}
	client.Finished.Wait()
	log.Panic("Client failed")
}
