package server

import (
	"context"
	"strings"

	"k8s.io/klog/v2"

	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

func migratePolicyNames() error {
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
		policy.Name = updateName(policy.Name)
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
		policy.Name = updateName(policy.Name)
		_, err = calicoClient.GlobalNetworkPolicies().Update(context.Background(), &policy, options.SetOptions{})
		if err != nil {
			return err
		}
	}

	return nil
}

func updateName(name string) string {
	if strings.HasPrefix(name, "default.") {
		name = strings.TrimPrefix(name, "default.")
	}
	return name
}

func updateNeeded() bool {
	return true
}
