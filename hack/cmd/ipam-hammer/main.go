package main

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/smithy-go/ptr"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/winutils"
)

func main() {
	// Create a Kubernetes client.
	cs, c, err := getClients(os.Getenv("KUBECONFIG"))
	if err != nil {
		panic(err)
	}

	ctx := context.TODO()

	// Create a bunch of fake nodes, and assign random IPs to each.
	numNodes := 150
	logrus.Info("Creating nodes")
	done := make(chan error)
	for i := range numNodes {
		go doNode(ctx, cs, c, i, done)
	}

	for range numNodes {
		<-done
	}

	// Now, delete the nodes! This should trigger our IPAM GC code....
	logrus.Info("Deleting nodes")
	for i := range numNodes {
		n := v1.Node{ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("test-node-%d", i),
			Labels: map[string]string{
				"test": "ipam",
			},
		}}
		err := cs.CoreV1().Nodes().Delete(ctx, n.Name, metav1.DeleteOptions{})
		if err != nil {
			panic(err)
		}
	}
}

func doNode(ctx context.Context, cs *kubernetes.Clientset, c client.Interface, i int, done chan error) {
	defer func() {
		done <- nil
	}()

	// Create a node.
	n := v1.Node{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("test-node-%d", i)}}
	_, err := cs.CoreV1().Nodes().Create(ctx, &n, metav1.CreateOptions{})
	if err != nil && !errors.IsAlreadyExists(err) {
		panic(err)
	}

	// Assign a tunnel IP to the node.
	attrs := map[string]string{
		ipam.AttributeNode: n.Name,
		ipam.AttributeType: ipam.AttributeTypeIPIP,
	}
	handle := fmt.Sprintf("ipip-tunnel-addr-%s", n.Name)
	args := ipam.AutoAssignArgs{
		HandleID:    &handle,
		Attrs:       attrs,
		Hostname:    n.Name,
		IntendedUse: v3.IPPoolAllowedUseTunnel,
	}
	_, _, err = c.IPAM().AutoAssign(ctx, args)
	if err != nil {
		panic(err)
	}

	// Assign some pods IPs to the node.
	for j := range 10 {
		attrs = map[string]string{
			ipam.AttributePod:       fmt.Sprintf("pod-%s-%d", n.Name, j),
			ipam.AttributeNode:      n.Name,
			ipam.AttributeNamespace: "default",
		}
		args := ipam.AutoAssignArgs{
			HandleID:    ptr.String(fmt.Sprintf("pod-%s-%d", n.Name, j)),
			Num4:        1,
			Hostname:    n.Name,
			Attrs:       attrs,
			IntendedUse: v3.IPPoolAllowedUseWorkload,
		}
		_, _, err = c.IPAM().AutoAssign(ctx, args)
		if err != nil {
			panic(err)
		}
	}
}

// getClients builds and returns Kubernetes and Calico clients.
func getClients(kubeconfig string) (*kubernetes.Clientset, client.Interface, error) {
	config, err := apiconfig.LoadClientConfigFromEnvironment()
	if err != nil {
		return nil, nil, err
	}
	config.Spec.K8sClientQPS = 500

	// Get Calico client
	calicoClient, err := client.New(*config)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build Calico client: %s", err)
	}

	// Now build the Kubernetes client, we support in-cluster config and kubeconfig
	// as means of configuring the client.
	k8sconfig, err := winutils.BuildConfigFromFlags("", kubeconfig)
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
