// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.

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

package active

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/tigera/operator/pkg/common"
)

const (
	ActiveConfigMapName = "active-operator"
	activeNamespaceKey  = "active-namespace"
)

// GetActiveConfigMap returns the ConfigMap for the active operator if it
// exists. If the ConfigMap does not exist then no map is returned and no
// error. If there is a problem fetching the ConfigMap then the error is returned.
func GetActiveConfigMap(client client.Client) (*corev1.ConfigMap, error) {
	cm := &corev1.ConfigMap{}
	cmNamespacedName := types.NamespacedName{
		Name:      ActiveConfigMapName,
		Namespace: common.CalicoNamespace,
	}
	if err := client.Get(context.Background(), cmNamespacedName, cm); err != nil {
		// If the configmap is unavailable, do not return error
		if kerrors.IsNotFound(err) {
			return nil, nil
		} else {
			return nil, fmt.Errorf("failed to read ConfigMap %q: %s", ActiveConfigMapName, err)
		}
	}
	return cm, nil
}

var operatorNamespace = common.OperatorNamespace

// IsThisOperatorActive will process the passed in ConfigMap and check that
// this running operator is the active one based on the OperatorNamespace.
// The first return value is if this running operator is active.
// The 2nd return value is the namespace of the active operator, if the namespace
// is not in the ConfigMap then an empty string will be returned.
func IsThisOperatorActive(cm *corev1.ConfigMap) (bool, string) {
	if cm == nil {
		return true, operatorNamespace()
	}
	if cm.Data[activeNamespaceKey] == operatorNamespace() {
		return true, cm.Data[activeNamespaceKey]
	}

	return false, cm.Data[activeNamespaceKey]
}

// GenerateMyActiveConfigMap returns a ConfigMap that matches what the
// expected ConfigMap would be.
func GenerateMyActiveConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ActiveConfigMapName,
			Namespace: common.CalicoNamespace,
		},
		Data: map[string]string{
			activeNamespaceKey: operatorNamespace(),
		},
	}
}

var OsExitOverride = os.Exit
var TickerRateOverride = 1000 * time.Millisecond

func WaitUntilActive(cs *kubernetes.Clientset, client client.Client, ctx context.Context, log logr.Logger) {
	acm := GenerateMyActiveConfigMap()
	listWatch := cache.NewListWatchFromClient(cs.CoreV1().RESTClient(), "configmaps", acm.Namespace, fields.OneTermEqualSelector("metadata.name", acm.Name))

	handlers := cache.ResourceEventHandlerFuncs{AddFunc: func(obj interface{}) {}}
	indexers := cache.Indexers{}
	indexer, informer := cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: listWatch,
		ObjectType:    &corev1.ConfigMap{},
		Handler:       handlers,
		ResyncPeriod:  0,
		Indexers:      indexers,
	})

	stopCh := make(chan struct{})
	go informer.Run(stopCh)
	defer close(stopCh)

	syncTick := time.NewTicker(TickerRateOverride)
	defer syncTick.Stop()
	for !informer.HasSynced() {
		select {
		case <-syncTick.C:
		case <-ctx.Done():
			log.Info("waiting for informer to sync and has been requested to stop")
			OsExitOverride(0)
		}
	}

	inactiveReport := true
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	currentActive := ""

	for {
		item, exist, err := indexer.Get(acm)
		if err != nil {
			log.Error(err, "failed to query active operator status")
			OsExitOverride(1)
		}
		var cm *corev1.ConfigMap
		if !exist {
			cm = nil
		} else {
			cm = item.(*corev1.ConfigMap)
		}
		active, ns := IsThisOperatorActive(cm)
		if active {
			return
		} else if inactiveReport || currentActive != ns {
			log.WithValues("active-namespace", ns).Info("Inactive operator: waiting")
			inactiveReport = false
			currentActive = ns
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			log.Info("operator was not active and has been requested to stop")
			OsExitOverride(0)
		}
	}
}
