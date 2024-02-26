// Copyright (c) 2023 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package debugserver

import (
	"net"
	"net/http"
	httppprof "net/http/pprof"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
)

func StartDebugPprofServer(host string, port int) {
	log.Infof("Insecure debug port is enabled on %s:%d.", host, port)
	_ = httppprof.Profile // Make sure we don't accidentally lose the import.
	go func() {
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		for {
			log.Infof("Attempting to open debug port %s:%d", host, port)
			err := http.ListenAndServe(addr, nil)
			if err != nil {
				log.WithError(err).Error("Debug port HTTP server failed.  Will retry...")
				time.Sleep(time.Second)
			}
		}
	}()
}
