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
	"flag"
	"fmt"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/golang/protobuf/proto"
	. "github.com/onsi/ginkgo"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/push"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"

	capi "github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s"
	"github.com/projectcalico/libcalico-go/lib/client"
)

// Global config - these are set by arguments on the ginkgo command line.
var (
	k8sServerEndpoint string // e.g. "http://172.17.0.2:6443"
	felixIP           string // e.g. "172.17.0.3"
	felixHostname     string // e.g. "b6fc45dcc1cb"
	prometheusPushURL string // e.g. "http://172.17.0.3:9091"
	codeLevel         string // e.g. "master"
)

// Prometheus metrics.
var (
	gaugeVecHeapAllocBytes = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "k8sfv_heap_alloc_bytes",
		Help: "Occupancy measurement",
	}, []string{"process", "test_name", "test_step", "code_level"})
	gaugeVecOccupancyMeanBytes = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "k8sfv_occupancy_mean_bytes",
		Help: "Mean occupancy for a test",
	}, []string{"process", "test_name", "code_level"})
	gaugeVecOccupancyIncreasePercent = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "k8sfv_occupancy_increase_percent",
		Help: "% occupancy increase during a test",
	}, []string{"process", "test_name", "code_level"})
	gaugeVecTestResult = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "k8sfv_test_result",
		Help: "Test result, i.e. pass (1) or failure (0)",
	}, []string{"test_name", "code_level"})
)

var _ = BeforeSuite(func() {
	log.Info(">>> BeforeSuite <<<")
	// Get and log command line args.
	k8sServerEndpoint = flag.Arg(0)
	felixIP = flag.Arg(1)
	felixHostname = flag.Arg(2)
	prometheusPushURL = flag.Arg(3)
	codeLevel = flag.Arg(4)
	log.WithFields(log.Fields{
		"k8sServerEndpoint": k8sServerEndpoint,
		"felixIP":           felixIP,
		"felixHostname":     felixHostname,
		"prometheusPushURL": prometheusPushURL,
		"codeLevel":         codeLevel,
	}).Info("Args")

	// Register Prometheus metrics.
	prometheus.MustRegister(gaugeVecHeapAllocBytes)
	prometheus.MustRegister(gaugeVecOccupancyMeanBytes)
	prometheus.MustRegister(gaugeVecOccupancyIncreasePercent)
	prometheus.MustRegister(gaugeVecTestResult)
})

var testName string

var _ = JustBeforeEach(func() {
	log.Info(">>> JustBeforeEach <<<")
	testName = CurrentGinkgoTestDescription().FullTestText
})

var _ = AfterEach(func() {
	log.Info(">>> AfterEach <<<")
	result := float64(1)
	if CurrentGinkgoTestDescription().Failed {
		result = 0
	}
	gaugeVecTestResult.WithLabelValues(testName, codeLevel).Set(result)
})

var _ = AfterSuite(func() {
	log.Info(">>> AfterSuite <<<")
	if prometheusPushURL != "" {
		// Push metrics to Prometheus push gateway.
		err := push.FromGatherer(
			"k8sfv",
			nil,
			prometheusPushURL,
			prometheus.DefaultGatherer)
		panicIfError(err)
	}

	metricFamilies, err := prometheus.DefaultGatherer.Gather()
	panicIfError(err)
	fmt.Println("")
	for _, family := range metricFamilies {
		if strings.HasPrefix(*family.Name, "k8sfv") {
			fmt.Println(proto.MarshalTextString(family))
		}
	}
})

func initialize(k8sServerEndpoint string) (clientset *kubernetes.Clientset) {

	initializeCalicoDeployment(k8sServerEndpoint)

	config, err := clientcmd.NewNonInteractiveClientConfig(*api.NewConfig(),
		"",
		&clientcmd.ConfigOverrides{
			ClusterDefaults: api.Cluster{
				Server:                k8sServerEndpoint,
				InsecureSkipTLSVerify: true,
			},
		},
		clientcmd.NewDefaultClientConfigLoadingRules()).ClientConfig()
	if err != nil {
		panic(err)
	}

	config.QPS = 10000
	config.Burst = 20000
	clientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		panic(err)
	}

	return
}

func initializeCalicoDeployment(k8sServerEndpoint string) {
	// Create client into the Kubernetes datastore.
	c, err := client.New(capi.CalicoAPIConfig{
		Spec: capi.CalicoAPIConfigSpec{
			DatastoreType: capi.Kubernetes,
			KubeConfig: k8s.KubeConfig{
				K8sAPIEndpoint:           k8sServerEndpoint,
				K8sInsecureSkipTLSVerify: true,
			},
		},
	})
	if err != nil {
		panic(err)
	}

	// Establish the other global config that Calico requires.
	err = c.EnsureInitialized()
	if err != nil {
		panic(err)
	}
}

func create1000Pods(clientset *kubernetes.Clientset, nsPrefix string) error {

	d := NewDeployment(clientset, 49, true)
	nsName := nsPrefix + "test"

	// Create 1000 pods.
	createNamespace(clientset, nsName, nil)
	log.Info("Creating pods:")
	for i := 0; i < 1000; i++ {
		createPod(clientset, d, nsName, podSpec{})
	}
	log.Info("Done")

	return nil
}

func cleanupAll(clientset *kubernetes.Clientset, nsPrefix string) {
	cleanupAllPods(clientset, nsPrefix)
	cleanupAllNodes(clientset)
	cleanupAllNamespaces(clientset, nsPrefix)
}

func panicIfError(err error) {
	if err != nil {
		panic(err)
	}
	return
}
