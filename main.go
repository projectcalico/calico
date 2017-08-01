package main

import (
	"flag"
	"github.com/projectcalico/k8s-policy/pkg/controllers/namespace"
	"github.com/projectcalico/k8s-policy/pkg/controllers/pod"
	"github.com/projectcalico/libcalico-go/lib/client"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/tools/clientcmd"
	"os"
)

func main() {
	logLevel, err := log.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {

		// Defaulting log level to INFO
		logLevel = log.InfoLevel
	}

	log.SetLevel(logLevel)

	reconcilerPeriod, exists := os.LookupEnv("RECONCILER_PERIOD")
	if !exists {
		
		// Defaulting to 5 mins
		reconcilerPeriod = "5m"
	}

	controllerType, exists := os.LookupEnv("CONTROLLER_TYPE")
	if !exists {
		log.Fatal("Specify controller type using environment variable CONTROLLER_TYPE. Valid values are endpoint, profile, policy.")
	}

	k8sClientset, calicoClient, err := getClients()

	if err != nil {
		log.Fatal(err)
	}

	stop := make(chan struct{})
	defer close(stop)

	switch controllerType {
	case "endpoint":
		podController := pod.NewPodController(k8sClientset, calicoClient)
		go podController.Run(5, reconcilerPeriod, stop)
	case "profile":
		namespaceController := namespace.NewNamespaceController(k8sClientset, calicoClient)
		go namespaceController.Run(5, reconcilerPeriod, stop)
	case "policy":
	default:
		log.Fatal("Not a valid CONTROLLER_TYPE. Valid values are endpoint, profile, policy.")
	}

	// Wait forever.
	select {}
}

// Fuction that returns kubernetes and calico clients.
func getClients() (*kubernetes.Clientset, *client.Client, error) {
	cconfig, err := client.LoadClientConfig("")
	if err != nil {
		return nil, nil, err
	}

	// Get Calico client
	calicoClient, err := client.New(*cconfig)
	if err != nil {
		panic(err)
	}

	var kubeconfig string
	var master string

	flag.StringVar(&kubeconfig, "kubeconfig", "", "absolute path to the kubeconfig file")
	flag.StringVar(&master, "master", "", "master url")
	flag.Parse()

	// creates the connection
	k8sconfig, err := clientcmd.BuildConfigFromFlags(master, kubeconfig)
	if err != nil {
		log.Fatal(err)
	}
	if err != nil {
		return nil, nil, err
	}

	// Get kubenetes clientset
	k8sClientset, err := kubernetes.NewForConfig(k8sconfig)
	if err != nil {
		panic(err.Error())
	}

	return k8sClientset, calicoClient, nil
}
