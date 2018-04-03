// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/pkg/transport"
	"github.com/projectcalico/kube-controllers/pkg/config"
	"github.com/projectcalico/kube-controllers/pkg/controllers/namespace"
	"github.com/projectcalico/kube-controllers/pkg/controllers/networkpolicy"
	"github.com/projectcalico/kube-controllers/pkg/controllers/node"
	"github.com/projectcalico/kube-controllers/pkg/controllers/pod"
	"github.com/projectcalico/kube-controllers/pkg/controllers/serviceaccount"
	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/logutils"
	log "github.com/sirupsen/logrus"
	"k8s.io/apiserver/pkg/storage/etcd3"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// VERSION is filled out during the build process (using git describe output)
var VERSION string

func main() {
	// Configure log formatting.
	log.SetFormatter(&logutils.Formatter{})

	// Install a hook that adds file/line no information.
	log.AddHook(&logutils.ContextHook{})

	// If `-v` is passed, display the version and exit.
	// Use a new flag set so as not to conflict with existing libraries which use "flag"
	flagSet := flag.NewFlagSet("Calico", flag.ExitOnError)
	version := flagSet.Bool("v", false, "Display version")
	err := flagSet.Parse(os.Args[1:])
	if err != nil {
		log.WithError(err).Fatal("Failed to parse flags")
	}
	if *version {
		fmt.Println(VERSION)
		os.Exit(0)
	}

	// Attempt to load configuration.
	config := new(config.Config)
	if err = config.Parse(); err != nil {
		log.WithError(err).Fatal("Failed to parse config")
	}
	log.WithField("config", config).Info("Loaded configuration from environment")

	// Set the log level based on the loaded configuration.
	logLevel, err := log.ParseLevel(config.LogLevel)
	if err != nil {
		logLevel = log.InfoLevel
	}
	log.SetLevel(logLevel)

	// Build clients to be used by the controllers.
	k8sClientset, calicoClient, err := getClients(config.Kubeconfig)
	if err != nil {
		log.WithError(err).Fatal("Failed to start")
	}

	stop := make(chan struct{})
	defer close(stop)

	// Create the context.
	ctx := context.Background()

	log.Info("Ensuring Calico datastore is initialized")
	initCtx, cancelInit := context.WithTimeout(ctx, 10*time.Second)
	defer cancelInit()
	err = calicoClient.EnsureInitialized(initCtx, "", "k8s")
	if err != nil {
		log.WithError(err).Fatal("Failed to initialize Calico datastore")
	}

	for _, controllerType := range strings.Split(config.EnabledControllers, ",") {
		switch controllerType {
		case "workloadendpoint":
			podController := pod.NewPodController(ctx, k8sClientset, calicoClient)
			go podController.Run(config.WorkloadEndpointWorkers, config.ReconcilerPeriod, stop)
		case "profile", "namespace":
			namespaceController := namespace.NewNamespaceController(ctx, k8sClientset, calicoClient)
			go namespaceController.Run(config.ProfileWorkers, config.ReconcilerPeriod, stop)
		case "policy":
			policyController := networkpolicy.NewPolicyController(ctx, k8sClientset, calicoClient)
			go policyController.Run(config.PolicyWorkers, config.ReconcilerPeriod, stop)
		case "node":
			nodeController := node.NewNodeController(ctx, k8sClientset, calicoClient)
			go nodeController.Run(config.NodeWorkers, config.ReconcilerPeriod, stop)
		case "serviceaccount":
			serviceAccountController := serviceaccount.NewServiceAccountController(ctx, k8sClientset, calicoClient)
			go serviceAccountController.Run(config.ProfileWorkers, config.ReconcilerPeriod, stop)
		default:
			log.Fatalf("Invalid controller '%s' provided. Valid options are workloadendpoint, profile, policy", controllerType)
		}
	}

	// If configured to do so, start an etcdv3 compaction.
	startCompactor(ctx, config)

	// Wait forever.
	select {}
}

// Starts an etcdv3 compaction goroutine with the given config.
func startCompactor(ctx context.Context, config *config.Config) {
	interval, err := time.ParseDuration(config.CompactionPeriod)
	if err != nil {
		log.WithError(err).Fatal("Invalid compact interval")
	}

	if interval.Nanoseconds() == 0 {
		log.Info("Disabling periodic etcdv3 compaction")
		return
	}

	// Kick off a periodic compaction of etcd.
	etcdClient, err := newEtcdV3Client()
	if err != nil {
		log.WithError(err).Error("Failed to start etcd compaction routine")
	} else {
		log.WithField("period", interval).Info("Starting periodic etcdv3 compaction")
		etcd3.StartCompactor(ctx, etcdClient, interval)
	}
}

// getClients builds and returns Kubernetes and Calico clients.
func getClients(kubeconfig string) (*kubernetes.Clientset, client.Interface, error) {
	// Get Calico client
	calicoClient, err := client.NewFromEnv()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build Calico client: %s", err)
	}

	// Now build the Kubernetes client, we support in-cluster config and kubeconfig
	// as means of configuring the client.
	k8sconfig, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build kubernetes client config: %s", err)
	}

	// Get Kubernetes clientset
	k8sClientset, err := kubernetes.NewForConfig(k8sconfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build kubernetes client: %s", err)
	}

	return k8sClientset, calicoClient, nil
}

// Returns an etcdv3 client based on the environment. The client will be configured to
// match that in use by the libcalico-go client.
func newEtcdV3Client() (*clientv3.Client, error) {
	config, err := apiconfig.LoadClientConfigFromEnvironment()
	if err != nil {
		return nil, err
	}

	// Split the endpoints into a location slice.
	etcdLocation := []string{}
	if config.Spec.EtcdEndpoints != "" {
		etcdLocation = strings.Split(config.Spec.EtcdEndpoints, ",")
	}

	if len(etcdLocation) == 0 {
		log.Warning("No etcd endpoints specified in etcdv3 API config")
		return nil, fmt.Errorf("no etcd endpoints specified")
	}

	// Create the etcd client
	tlsInfo := &transport.TLSInfo{
		CAFile:   config.Spec.EtcdCACertFile,
		CertFile: config.Spec.EtcdCertFile,
		KeyFile:  config.Spec.EtcdKeyFile,
	}
	tls, _ := tlsInfo.ClientConfig()

	cfg := clientv3.Config{
		Endpoints:   etcdLocation,
		TLS:         tls,
		DialTimeout: 10 * time.Second,
	}

	// Plumb through the username and password if both are configured.
	if config.Spec.EtcdUsername != "" && config.Spec.EtcdPassword != "" {
		cfg.Username = config.Spec.EtcdUsername
		cfg.Password = config.Spec.EtcdPassword
	}

	return clientv3.New(cfg)
}
