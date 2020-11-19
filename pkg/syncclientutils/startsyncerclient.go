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
	"errors"
	"fmt"
	"net"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/typha/pkg/syncclient"
	"github.com/projectcalico/typha/pkg/syncproto"
)

// MustStartSyncerClientIfTyphaConfigured starts a syncer of the requested type if typha is configured to be running.
// - This returns true if the syncer was started successfully.
// - This returns false if typha is not configured to be running.
// - This logs and exits if typha is configured but it failed to locate the service or connect a syncer client.
//
// The typha address may be directly configured in the typha config, or will otherwise be looked by finding the
// associated Kubernetes service.
func MustStartSyncerClientIfTyphaConfigured(typhaConfig *TyphaConfig, syncerType syncproto.SyncerType,
	myVersion, myHostname, myInfo string,
	cbs api.SyncerCallbacks,
) bool {
	typhaAddr, err := discoverTyphaAddr(typhaConfig)
	if err != nil {
		log.WithError(err).Fatal("Typha discovery enabled but discovery failed.")
	}
	if typhaAddr == "" {
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

var ErrServiceNotReady = errors.New("Kubernetes service missing IP or port.")

// discoverTyphaAddr attempts to discover the typha kubernetes service.
// -  If an address is explicitly specified, return that
// -  If a kubernetes service name is specified then use that to look up the service
// -  Otherwise, assume typha is not configured and return an empty addr string.
func discoverTyphaAddr(typhaConfig *TyphaConfig) (string, error) {
	if typhaConfig.Addr != "" {
		// Explicit address; trumps other sources of config.
		return typhaConfig.Addr, nil
	}

	if typhaConfig.K8sServiceName == "" {
		// No explicit address, and no service name, not using Typha.
		return "", nil
	}

	// If we get here, we need to look up the Typha service using the k8s API.
	// TODO Typha: support Typha lookup without using rest.InClusterConfig().
	k8sconf, err := rest.InClusterConfig()
	if err != nil {
		log.WithError(err).Error("Unable to create Kubernetes config.")
		return "", err
	}
	clientset, err := kubernetes.NewForConfig(k8sconf)
	if err != nil {
		log.WithError(err).Error("Unable to create Kubernetes client set.")
		return "", err
	}
	svcClient := clientset.CoreV1().Services(typhaConfig.K8sNamespace)
	svc, err := svcClient.Get(context.Background(), typhaConfig.K8sServiceName, v1.GetOptions{})
	if err != nil {
		log.WithError(err).Error("Unable to get Typha service from Kubernetes.")
		return "", err
	}
	host := svc.Spec.ClusterIP
	log.WithField("clusterIP", host).Info("Found Typha ClusterIP.")
	if host == "" {
		log.WithError(err).Error("Typha service had no ClusterIP.")
		return "", ErrServiceNotReady
	}
	for _, p := range svc.Spec.Ports {
		if p.Name == "calico-typha" {
			log.WithField("port", p).Info("Found Typha service port.")
			typhaAddr := net.JoinHostPort(host, fmt.Sprintf("%v", p.Port))
			return typhaAddr, nil
		}
	}
	log.Error("Didn't find Typha service port.")
	return "", ErrServiceNotReady
}
