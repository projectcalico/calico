package main

import (
	"fmt"
	"github.com/projectcalico/k8s-policy/pkg/config"
	"github.com/projectcalico/k8s-policy/pkg/controllers/namespace"
	"github.com/projectcalico/k8s-policy/pkg/controllers/networkpolicy"
	"github.com/projectcalico/k8s-policy/pkg/controllers/pod"
	"github.com/projectcalico/libcalico-go/lib/client"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	// Initialize logger to info level.  This may be adjusted once
	// config is loaded.
	log.SetLevel(log.InfoLevel)

	// Attempt to load configuration.
	config := new(config.Config)
	err := config.Parse()
	if err != nil {
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

	// TODO: Allow user define multiple types of controllers.
	switch config.ControllerType {
	case "endpoint":
		podController := pod.NewPodController(k8sClientset, calicoClient)
		go podController.Run(config.EndpointWorkers, config.ReconcilerPeriod, stop)
	case "profile":
		namespaceController := namespace.NewNamespaceController(k8sClientset, calicoClient)
		go namespaceController.Run(config.ProfileWorkers, config.ReconcilerPeriod, stop)
	case "policy":
		policyController := networkpolicy.NewPolicyController(k8sClientset, calicoClient)
		go policyController.Run(config.PolicyWorkers, config.ReconcilerPeriod, stop)
	default:
		log.Fatal("Not a valid CONTROLLER_TYPE. Valid values are endpoint, profile, policy.")
	}

	// Wait forever.
	select {}
}

// getClients builds and returns both Kubernetes and Calico clients.
func getClients(kubeconfig string) (*kubernetes.Clientset, *client.Client, error) {
	// First, build the Calico client using the configured environment variables.
	cconfig, err := client.LoadClientConfig("")
	if err != nil {
		return nil, nil, err
	}

	// Get Calico client
	calicoClient, err := client.New(*cconfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build Calico client: %s", err)
	}

	// Now build the Kubernetes client, we support in-cluster config and kubeconfig
	// as means of configuring the client.
	k8sconfig, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build kubernetes client config: %s", err)
	}

	// Get kubenetes clientset
	k8sClientset, err := kubernetes.NewForConfig(k8sconfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build kubernetes client: %s", err)
	}

	return k8sClientset, calicoClient, nil
}
