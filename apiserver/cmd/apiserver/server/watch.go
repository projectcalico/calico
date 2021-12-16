// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package server

import (
	"fmt"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	authConfigMap          = "extension-apiserver-authentication"
	authConfigMapNamespace = "kube-system"
)

// WatchExtensionAuth watches the ConfigMap extension-apiserver-authentication
// and returns true if its resource version changes or a watch event indicates
// it changed. The cfg is used to get a k8s client for getting and watching the
// ConfigMap. If stopChan is closed then the function will return no change.
func WatchExtensionAuth(stopChan chan struct{}) (bool, error) {
	//TODO: Use SharedInformerFactory rather than creating new client.

	// set up k8s client
	// attempt 1: KUBECONFIG env var
	cfgFile := os.Getenv("KUBECONFIG")
	cfg, err := clientcmd.BuildConfigFromFlags("", cfgFile)
	if err != nil {
		// attempt 2: in cluster config
		if cfg, err = rest.InClusterConfig(); err != nil {
			return false, err
		}
	}

	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return false, fmt.Errorf("Failed to get client to watch extension auth ConfigMap: %v", err)
	}

	changed := false
	synced := false

	watcher := cache.NewListWatchFromClient(
		client.CoreV1().RESTClient(),
		"configmaps",
		authConfigMapNamespace,
		fields.OneTermEqualSelector("metadata.name", authConfigMap))

	_, controller := cache.NewInformer(
		watcher,
		&corev1.ConfigMap{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(_ interface{}) {
				if synced {
					changed = true
					close(stopChan)
				}
			},
			DeleteFunc: func(_ interface{}) {
				if synced {
					changed = true
					close(stopChan)
				}
			},
			UpdateFunc: func(old, new interface{}) {
				if synced {
					o := old.(*corev1.ConfigMap)
					n := new.(*corev1.ConfigMap)
					// Only detect as changed if the version has changed
					if o.ResourceVersion != n.ResourceVersion {
						changed = true
						close(stopChan)
					}
				}
			},
		})

	go func() {
		for !controller.HasSynced() {
			time.Sleep(50 * time.Millisecond)
		}
		synced = true
	}()

	controller.Run(stopChan)

	return changed, nil
}
