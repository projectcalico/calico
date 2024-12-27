package server

import (
	"context"
	"fmt"
	"os"
	"strings"

	v1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/winutils"
)

func migratePolicyNames() error {
	k8sconfig, err := winutils.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	if err != nil {
		return fmt.Errorf("failed to build kubernetes client config: %s", err)
	}

	// Get Kubernetes clientset
	k8sClientset, err := kubernetes.NewForConfig(k8sconfig)
	if err != nil {
		return fmt.Errorf("failed to build kubernetes client: %s", err)
	}
	if !updateNeeded(k8sClientset) {
		return nil
	}
	klog.Infof("Migrating policy names")
	calicoClient, err := client.NewFromEnv()
	if err != nil {
		return err
	}

	networkPolicies, err := calicoClient.NetworkPolicies().List(context.Background(), options.ListOptions{})
	if err != nil {
		return err
	}
	for _, policy := range networkPolicies.Items {
		policy.Name = removeDefaultTierPrefix(policy.Name)
		_, err = calicoClient.NetworkPolicies().Update(context.Background(), &policy, options.SetOptions{})
		if err != nil {
			return err
		}
	}

	globalNetworkPolicies, err := calicoClient.GlobalNetworkPolicies().List(context.Background(), options.ListOptions{})
	if err != nil {
		return err
	}
	for _, policy := range globalNetworkPolicies.Items {
		policy.Name = removeDefaultTierPrefix(policy.Name)
		_, err = calicoClient.GlobalNetworkPolicies().Update(context.Background(), &policy, options.SetOptions{})
		if err != nil {
			return err
		}
	}

	return nil
}

func removeDefaultTierPrefix(name string) string {
	if strings.HasPrefix(name, "default.") {
		name = strings.TrimPrefix(name, "default.")
	}
	return name
}

func updateNeeded(k8sClientset *kubernetes.Clientset) bool {
	tierMigration, err := k8sClientset.CoreV1().ConfigMaps("calico-apiserver").Get(context.Background(), "api-server", metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			configMap := v1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tier-migration",
					Namespace: "calico-apiserver",
				},
				Data: map[string]string{
					"tierMigration": "true",
				},
			}
			_, err = k8sClientset.CoreV1().ConfigMaps("calico-apiserver").Create(context.Background(), &configMap, metav1.CreateOptions{})
			if err != nil {
				klog.Errorf("Failed to create api-server configmap: %s", err)
				return false
			}

			return true
		} else {
			klog.Errorf("Failed to get api-server configmap: %s", err)
			return false
		}
	}
	if tierMigration.Data["tierMigration"] == "false" {
		return false
	}
	return true
}
