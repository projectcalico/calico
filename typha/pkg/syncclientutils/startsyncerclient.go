// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package syncclientutils

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"

	"github.com/projectcalico/calico/typha/pkg/discovery"
	"github.com/projectcalico/calico/typha/pkg/syncclient"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
)

// MustStartSyncerClientIfTyphaConfigured starts a syncer of the requested type if typha is configured to be running.
// - This returns true if the syncer was started successfully.
// - This returns false if typha is not configured to be running.
// - This logs and exits if typha is configured but it failed to locate the service or connect a syncer client.
//
// The typha address may be directly configured in the typha config, or will otherwise be looked by finding the
// associated Kubernetes service.
func MustStartSyncerClientIfTyphaConfigured(
	typhaConfig *TyphaConfig,
	syncerType syncproto.SyncerType,
	myVersion, myHostname, myInfo string,
	cbs api.SyncerCallbacks,
) bool {
	typhaAddr, err := discovery.DiscoverTyphaAddrs(
		discovery.WithAddrOverride(typhaConfig.Addr),
		discovery.WithInClusterKubeClient(), /* defer creation of a client until its needed. */
		discovery.WithKubeService(typhaConfig.K8sNamespace, typhaConfig.K8sServiceName),
	)
	if err != nil {
		log.WithError(err).Fatal("Typha discovery enabled but discovery failed.")
	}
	if len(typhaAddr) == 0 {
		log.Debug("Typha is not configured")
		return false
	}

	// Use a remote Syncer, via the Typha server.
	log.WithField("addr", typhaAddr).Info("Connecting to Typha.")
	typhaConnection := syncclient.New(
		typhaAddr,
		myVersion, myHostname, myInfo,
		cbs,
		&syncclient.Options{
			SyncerType:   syncerType,
			ReadTimeout:  typhaConfig.ReadTimeout,
			WriteTimeout: typhaConfig.WriteTimeout,
			KeyFile:      typhaConfig.KeyFile,
			CertFile:     typhaConfig.CertFile,
			CAFile:       typhaConfig.CAFile,
			ServerCN:     typhaConfig.CN,
			ServerURISAN: typhaConfig.URISAN,
		},
	)
	if err := typhaConnection.Start(context.Background()); err != nil {
		log.WithError(err).Fatal("Failed to connect to Typha")
	}
	go func() {
		typhaConnection.Finished.Wait()
		log.Fatal("Connection to Typha failed")
	}()

	return true
}
