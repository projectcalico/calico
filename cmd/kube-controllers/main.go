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
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/pkg/transport"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"k8s.io/apiserver/pkg/storage/etcd3"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/logutils"

	"github.com/projectcalico/kube-controllers/pkg/config"
	"github.com/projectcalico/kube-controllers/pkg/controllers/controller"
	"github.com/projectcalico/kube-controllers/pkg/controllers/namespace"
	"github.com/projectcalico/kube-controllers/pkg/controllers/networkpolicy"
	"github.com/projectcalico/kube-controllers/pkg/controllers/node"
	"github.com/projectcalico/kube-controllers/pkg/controllers/pod"
	"github.com/projectcalico/kube-controllers/pkg/controllers/serviceaccount"
	"github.com/projectcalico/kube-controllers/pkg/status"
)

// VERSION is filled out during the build process (using git describe output)
var VERSION string

func main() {
	// Configure log formatting.
	log.SetFormatter(&logutils.Formatter{})

	// Install a hook that adds file/line no information.
	log.AddHook(&logutils.ContextHook{})

	// Tell glog (used by client-go) to log into STDERR. Otherwise, we risk
	// certain kinds of API errors getting logged into a directory not
	// available in a `FROM scratch` Docker container, causing glog to abort
	// hard with an exit code > 0.
	err := flag.Set("logtostderr", "true")
	if err != nil {
		log.WithError(err).Fatal("Failed configure logging")
	}

	// If `-v` is passed, display the version and exit.
	// Use a new flag set so as not to conflict with existing libraries which use "flag"
	flagSet := pflag.NewFlagSet("Calico", pflag.ExitOnError)
	version := flagSet.BoolP("version", "v", false, "Display version")
	err = flagSet.Parse(os.Args[1:])
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

	controllerCtrl := &controllerControl{
		ctx:              ctx,
		controllerStates: make(map[string]*controllerState),
		config:           config,
		stop:             stop,
	}

	// Create the status file. We will only update it if we have healthchecks enabled.
	s := status.New(status.DefaultStatusFile)

	for _, controllerType := range strings.Split(config.EnabledControllers, ",") {
		switch controllerType {
		case "workloadendpoint":
			podController := pod.NewPodController(ctx, k8sClientset, calicoClient)
			controllerCtrl.controllerStates["Pod"] = &controllerState{
				controller:  podController,
				threadiness: config.WorkloadEndpointWorkers,
			}
		case "profile", "namespace":
			namespaceController := namespace.NewNamespaceController(ctx, k8sClientset, calicoClient)
			controllerCtrl.controllerStates["Namespace"] = &controllerState{
				controller:  namespaceController,
				threadiness: config.ProfileWorkers,
			}
		case "policy":
			policyController := networkpolicy.NewPolicyController(ctx, k8sClientset, calicoClient)
			controllerCtrl.controllerStates["NetworkPolicy"] = &controllerState{
				controller:  policyController,
				threadiness: config.PolicyWorkers,
			}
		case "node":
			nodeController := node.NewNodeController(ctx, k8sClientset, calicoClient, config)
			controllerCtrl.controllerStates["Node"] = &controllerState{
				controller:  nodeController,
				threadiness: config.NodeWorkers,
			}
		case "serviceaccount":
			serviceAccountController := serviceaccount.NewServiceAccountController(ctx, k8sClientset, calicoClient)
			controllerCtrl.controllerStates["ServiceAccount"] = &controllerState{
				controller:  serviceAccountController,
				threadiness: config.ProfileWorkers,
			}
		default:
			log.Fatalf("Invalid controller '%s' provided.", controllerType)
		}
	}

	if config.DatastoreType == "etcdv3" {
		// If configured to do so, start an etcdv3 compaction.
		go startCompactor(ctx, config)
	}

	// Run the health checks on a separate goroutine.
	if config.HealthEnabled {
		log.Info("Starting status report routine")
		go runHealthChecks(ctx, s, k8sClientset, calicoClient)
	}

	// Run the controllers. This runs indefinitely.
	controllerCtrl.RunControllers()
}

// Run the controller health checks.
func runHealthChecks(ctx context.Context, s *status.Status, k8sClientset *kubernetes.Clientset, calicoClient client.Interface) {
	s.SetReady("CalicoDatastore", false, "initialized to false")
	s.SetReady("KubeAPIServer", false, "initialized to false")

	// Loop forever and perform healthchecks.
	for {
		// skip healthchecks if configured
		// Datastore HealthCheck
		healthCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := calicoClient.EnsureInitialized(healthCtx, "", "k8s")
		if err != nil {
			log.WithError(err).Errorf("Failed to verify datastore")
			s.SetReady(
				"CalicoDatastore",
				false,
				fmt.Sprintf("Error verifying datastore: %v", err),
			)
		} else {
			s.SetReady("CalicoDatastore", true, "")
		}
		cancel()

		// Kube-apiserver HealthCheck
		healthStatus := 0
		k8sCheckDone := make(chan interface{}, 1)
		go func(k8sCheckDone <-chan interface{}) {
			time.Sleep(2 * time.Second)
			select {
			case <-k8sCheckDone:
				// The check has completed.
			default:
				// Check is still running, so report not ready.
				s.SetReady(
					"KubeAPIServer",
					false,
					fmt.Sprintf("Error reaching apiserver: taking a long time to check apiserver"),
				)
			}
		}(k8sCheckDone)
		k8sClientset.Discovery().RESTClient().Get().AbsPath("/healthz").Do().StatusCode(&healthStatus)
		k8sCheckDone <- nil
		if healthStatus != http.StatusOK {
			log.WithError(err).Errorf("Failed to reach apiserver")
			s.SetReady(
				"KubeAPIServer",
				false,
				fmt.Sprintf("Error reaching apiserver: %v with http status code: %d", err, healthStatus),
			)
		} else {
			s.SetReady("KubeAPIServer", true, "")
		}

		time.Sleep(10 * time.Second)
	}
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

	// Kick off a periodic compaction of etcd, retry until success.
	for {
		etcdClient, err := newEtcdV3Client()
		if err != nil {
			log.WithError(err).Error("Failed to start etcd compaction routine, retry in 1m")
			time.Sleep(1 * time.Minute)
			continue
		}

		log.WithField("period", interval).Info("Starting periodic etcdv3 compaction")
		etcd3.StartCompactor(ctx, etcdClient, interval)
		break
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

// Object for keeping track of controller states and statuses.
type controllerControl struct {
	ctx              context.Context
	controllerStates map[string]*controllerState
	config           *config.Config
	stop             chan struct{}
}

// Runs all the controllers and blocks indefinitely.
func (cc *controllerControl) RunControllers() {
	for controllerType, cs := range cc.controllerStates {
		log.WithField("ControllerType", controllerType).Info("Starting controller")
		go cs.controller.Run(cs.threadiness, cc.config.ReconcilerPeriod, cc.stop)
	}
	select {}
}

// Object for keeping track of Controller information.
type controllerState struct {
	controller  controller.Controller
	threadiness int
}
