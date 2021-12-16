// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/typha/pkg/daemon"
)

// main is the entry point to the calico-typha binary.
//
// Its main role is to sequence Typha's startup by:
//
// Initialising early logging config (log format and early debug settings).
//
// Parsing command line parameters.
//
// Loading datastore configuration from the environment or config file.
//
// Loading more configuration from the datastore (this is retried until success).
//
// Starting the fan-out proxy.
//
// Starting the usage reporting and prometheus metrics endpoint threads (if configured).
//
// Then, it defers to monitorAndManageShutdown(), which blocks until one of the components
// fails, then attempts a graceful shutdown.  At that point, all the processing is in
// background goroutines.
//
// To avoid having to maintain rarely-used code paths, Typha handles updates to its
// main config parameters by exiting and allowing itself to be restarted by the init
// daemon.
func main() {
	typha := daemon.New()
	err := typha.InitializeAndServeForever(context.Background())
	logrus.WithError(err).Panic("InitializeAndServeForever returned")
}
