// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package cloud

import (
	"maps"
	"os"
	"time"

	"github.com/tigera/operator/pkg/common"
	ctrl "sigs.k8s.io/controller-runtime"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

var configWatchLog = ctrl.Log.WithName("cloud_config_watch")

// watch spawns a goroutine which should exit if a configmap's data is changed.
// it is stubbed for testing.
var watch = func(cs kubernetes.Interface, cmData map[string]string) error {
	informer := cache.NewSharedInformer(
		cache.NewListWatchFromClient(
			cs.CoreV1().RESTClient(),
			"configmaps",
			common.OperatorNamespace(),
			fields.OneTermEqualSelector("metadata.name", configMapName),
		),
		&v1.ConfigMap{},
		0, // no resync period
	)
	_, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(_, newObj interface{}) {
			if !maps.Equal(cmData, newObj.(*v1.ConfigMap).Data) {
				configWatchLog.Info("detected config change. rebooting")
				os.Exit(0)
			} else {
				configWatchLog.Info("ignoring configmap update as data was not modified")
			}
		},
		AddFunc: func(obj interface{}) {
			if !maps.Equal(cmData, obj.(*v1.ConfigMap).Data) {
				configWatchLog.Info("detected config creation change. rebooting")
				os.Exit(0)
			} else {
				configWatchLog.Info("ignoring configmap creation as data was not modified")
			}
		},
	})
	if err != nil {
		return err
	}

	go informer.Run(make(chan struct{}))
	for !informer.HasSynced() {
		time.Sleep(1 * time.Second)
	}
	return nil
}
