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

package discovery

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var ErrServiceNotReady = errors.New("Kubernetes service missing IP or port")

type Typha struct {
	Addr     string
	IP       string
	NodeName *string
}

type options struct {
	addrOverride string

	k8sClient          kubernetes.Interface
	k8sServiceName     string
	k8sNamespace       string
	k8sServicePortName string
	inCluster          bool
}

type Option func(opts *options)

func WithAddrOverride(addr string) Option {
	return func(opts *options) {
		opts.addrOverride = addr
	}
}

func WithKubeClient(client kubernetes.Interface) Option {
	return func(opts *options) {
		opts.k8sClient = client
	}
}

// WithInClusterKubeClient enables auto-connection to Kubernetes using the in-cluster client config.
// this is disabled by default to avoid creating an extra Kubernetes client that is then discarded.
func WithInClusterKubeClient() Option {
	return func(opts *options) {
		opts.inCluster = true
	}
}

func WithKubeService(namespaceName, serviceName string) Option {
	return func(opts *options) {
		opts.k8sNamespace = namespaceName
		opts.k8sServiceName = serviceName
	}
}

func WithKubeServicePortNameOverride(portName string) Option {
	return func(opts *options) {
		opts.k8sServicePortName = portName
	}
}

// DiscoverTyphaAddr tries to discover the best address to use to connect to Typha.
//
// If an AddrOverride is supplied then that takes precedence, otherwise, DiscoverTyphaAddr will
// try to lookup one of the backend endpoints of the typha service (using the K8sServiceName and
// K8sNamespace fields).
//
// Returns "" if typha is not enabled (i.e. fields are empty).
func DiscoverTyphaAddr(opts ...Option) (Typha, error) {
	options := options{
		k8sServicePortName: "calico-typha",
	}

	for _, o := range opts {
		o(&options)
	}

	if options.addrOverride != "" {
		// Explicit address; trumps other sources of config.
		return Typha{
			Addr: options.addrOverride,
		}, nil
	}

	if options.k8sServiceName == "" {
		// No explicit address, and no service name, not using Typha.
		return Typha{}, nil
	}

	// If we get here, we need to look up the Typha service using the k8s API.
	if options.k8sClient == nil && options.inCluster {
		// Client didn't provide a kube client but we're allowed to create one.
		k8sConf, err := rest.InClusterConfig()
		if err != nil {
			logrus.WithError(err).Error("Unable to create in-cluster Kubernetes config.")
			return Typha{}, err
		}
		options.k8sClient, err = kubernetes.NewForConfig(k8sConf)
		if err != nil {
			logrus.WithError(err).Error("Unable to create Kubernetes client set.")
			return Typha{}, err
		}
	} else if options.k8sClient == nil {
		return Typha{}, errors.New("failed to look up Typha, no Kubernetes client available")
	}

	// If we get here, we need to look up the Typha service endpoints using the k8s API.
	epClient := options.k8sClient.CoreV1().Endpoints(options.k8sNamespace)
	eps, err := epClient.Get(context.Background(), options.k8sServiceName, v1.GetOptions{})
	if err != nil {
		logrus.WithError(err).Error("Unable to get Typha service endpoints from Kubernetes.")
		return Typha{}, err
	}

	candidates := set.New()

	for _, subset := range eps.Subsets {
		var portForOurVersion int32
		for _, port := range subset.Ports {
			if port.Name == options.k8sServicePortName {
				portForOurVersion = port.Port
				break
			}
		}

		if portForOurVersion == 0 {
			continue
		}

		// If we get here, this endpoint supports the typha port we're looking for.
		for _, h := range subset.Addresses {
			typhaAddr := net.JoinHostPort(h.IP, fmt.Sprint(portForOurVersion))
			candidates.Add(Typha{
				Addr:     typhaAddr,
				IP:       h.IP,
				NodeName: h.NodeName,
			})
		}
	}

	if candidates.Len() == 0 {
		logrus.Error("Didn't find any ready Typha instances.")
		return Typha{}, ErrServiceNotReady
	}

	var addrs []Typha
	candidates.Iter(func(item interface{}) error {
		typhaAddr := item.(Typha)
		addrs = append(addrs, typhaAddr)
		return nil
	})
	logrus.WithField("addrs", addrs).Info("Found ready Typha addresses.")
	n := rand.Intn(len(addrs))
	chosenAddr := addrs[n]
	logrus.WithField("choice", chosenAddr).Info("Chose Typha to connect to.")

	return chosenAddr, nil
}
