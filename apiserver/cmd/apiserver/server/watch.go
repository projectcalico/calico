// Copyright (c) 2019-2024 Tigera, Inc. All rights reserved.

package server

import (
	"context"
	"fmt"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/libcalico-go/lib/winutils"
)

const (
	authConfigMap          = "extension-apiserver-authentication"
	authConfigMapNamespace = "kube-system"
)

// WatchExtensionAuth watches the ConfigMap extension-apiserver-authentication
// and returns true if its resource version changes or a watch event indicates
// it changed. The cfg is used to get a k8s client for getting and watching the
// ConfigMap.
func WatchExtensionAuth(ctx context.Context) (bool, error) {
	//TODO: Use SharedInformerFactory rather than creating new client.

	// Create a new context with cancel.
	ctx, cancel := context.WithCancel(ctx)

	// set up k8s client
	// attempt 1: KUBECONFIG env var
	cfgFile := os.Getenv("KUBECONFIG")
	cfg, err := winutils.BuildConfigFromFlags("", cfgFile)
	if err != nil {
		// attempt 2: in cluster config
		if cfg, err = winutils.GetInClusterConfig(); err != nil {
			cancel()
			return false, err
		}
	}

	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		cancel()
		return false, fmt.Errorf("Failed to get client to watch extension auth ConfigMap: %v", err)
	}

	changed := false
	synced := false

	watcher := cache.NewListWatchFromClient(
		client.CoreV1().RESTClient(),
		"configmaps",
		authConfigMapNamespace,
		fields.OneTermEqualSelector("metadata.name", authConfigMap))

	_, controller := cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: watcher,
		ObjectType:    &corev1.ConfigMap{},
		ResyncPeriod:  0,
		Handler: cache.ResourceEventHandlerFuncs{
			AddFunc: func(_ interface{}) {
				if synced {
					changed = true
					cancel()
				}
			},
			DeleteFunc: func(_ interface{}) {
				if synced {
					changed = true
					cancel()
				}
			},
			UpdateFunc: func(old, new interface{}) {
				if synced {
					o := old.(*corev1.ConfigMap)
					n := new.(*corev1.ConfigMap)
					// Only detect as changed if the version has changed
					if o.ResourceVersion != n.ResourceVersion {
						changed = true
						cancel()
					}
				}
			},
		},
	})

	go func() {
		for !controller.HasSynced() {
			time.Sleep(50 * time.Millisecond)
		}
		synced = true
	}()

	controller.Run(ctx.Done())

	return changed, nil
}
