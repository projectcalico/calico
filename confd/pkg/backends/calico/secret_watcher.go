// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package calico

import (
	"fmt"
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/libcalico-go/lib/winutils"
)

type secretWatchData struct {
	// The channel that we should write to when we no longer want this watch.
	stopCh chan struct{}

	// Stale marker.
	stale bool

	// Secret value.
	secret *v1.Secret
}

type secretWatcher struct {
	client       *client
	namespace    string
	k8sClientset *kubernetes.Clientset
	mutex        sync.Mutex
	watches      map[string]*secretWatchData
}

func NewSecretWatcher(c *client) (*secretWatcher, error) {
	sw := &secretWatcher{
		client:  c,
		watches: make(map[string]*secretWatchData),
	}

	// Find the namespace we're running in.
	sw.namespace = os.Getenv("NAMESPACE")
	if sw.namespace == "" {
		// Default to kube-system.
		sw.namespace = "kube-system"
	}

	// set up k8s client
	// attempt 1: KUBECONFIG env var
	cfgFile := os.Getenv("KUBECONFIG")
	cfg, err := winutils.BuildConfigFromFlags("", cfgFile)
	if err != nil {
		log.WithError(err).Info("KUBECONFIG environment variable not found, attempting in-cluster")
		// attempt 2: in cluster config
		if cfg, err = winutils.GetInClusterConfig(); err != nil {
			return nil, err
		}
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	sw.k8sClientset = clientset

	return sw, nil
}

func (sw *secretWatcher) MarkStale() {
	sw.mutex.Lock()
	defer sw.mutex.Unlock()

	for _, watchData := range sw.watches {
		watchData.stale = true
	}
}

func (sw *secretWatcher) ensureWatchingSecret(name string) {
	if _, ok := sw.watches[name]; ok {
		log.Debugf("Already watching secret '%v' (namespace %v)", name, sw.namespace)
	} else {
		log.Debugf("Start a watch for secret '%v' (namespace %v)", name, sw.namespace)
		// We're not watching this secret yet, so start a watch for it.
		watcher := cache.NewListWatchFromClient(sw.k8sClientset.CoreV1().RESTClient(), "secrets", sw.namespace, fields.OneTermEqualSelector("metadata.name", name))
		_, controller := cache.NewInformerWithOptions(cache.InformerOptions{
			ListerWatcher: watcher,
			ObjectType:    &v1.Secret{},
			ResyncPeriod:  0,
			Handler:       sw,
		})
		sw.watches[name] = &secretWatchData{stopCh: make(chan struct{})}
		go controller.Run(sw.watches[name].stopCh)
		log.Debugf("Controller for secret '%v' is now running", name)

		// Block for up to 0.5s until the controller has synced.  This is just an
		// optimization to avoid churning the emitted BGP peer config when the secret is
		// already available.  If the secret takes a bit longer to appear, we will cope
		// with that too, but asynchronously and with some possible BIRD config churn.
		sw.allowTimeForControllerSync(name, controller, 500*time.Millisecond)
	}
}

func (sw *secretWatcher) allowTimeForControllerSync(name string, controller cache.Controller, timeAllowed time.Duration) {
	sw.mutex.Unlock()
	defer sw.mutex.Lock()
	log.Debug("Unlocked")

	startTime := time.Now()
	for {
		// Note: There is a lock associated with the controller's Queue, and HasSynced()
		// needs to take and release that lock.  The same lock is held when the controller
		// calls our OnAdd, OnUpdate and OnDelete callbacks.
		if controller.HasSynced() {
			log.Debugf("Controller for secret '%v' has synced", name)
			break
		} else {
			log.Debugf("Controller for secret '%v' has not synced yet", name)
		}
		if time.Since(startTime) > timeAllowed {
			log.Warningf("Controller for secret '%v' did not sync within %v", name, timeAllowed)
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	log.Debug("Relock...")
}

func (sw *secretWatcher) GetSecret(name, key string) (string, error) {
	sw.mutex.Lock()
	defer sw.mutex.Unlock()
	log.Debugf("Get secret for name '%v' key '%v'", name, key)

	// Ensure that we're watching this secret.
	sw.ensureWatchingSecret(name)

	// Mark it as still in use.
	sw.watches[name].stale = false

	// Get and decode the key of interest.
	if sw.watches[name].secret == nil {
		return "", fmt.Errorf("no data available for secret %v", name)
	}
	if data, ok := sw.watches[name].secret.Data[key]; ok {
		return string(data), nil
	} else {
		return "", fmt.Errorf("secret %v does not have key %v", name, key)
	}
}

func (sw *secretWatcher) SweepStale() {
	sw.mutex.Lock()
	defer sw.mutex.Unlock()

	for name, watchData := range sw.watches {
		if watchData.stale {
			close(watchData.stopCh)
			delete(sw.watches, name)
		}
	}
}

func (sw *secretWatcher) OnAdd(obj interface{}, isInInitialList bool) {
	log.Debug("Secret added")
	sw.updateSecret(obj.(*v1.Secret))
	sw.client.recheckPeerConfig()
}

func (sw *secretWatcher) OnUpdate(oldObj, newObj interface{}) {
	log.Debug("Secret updated")
	sw.updateSecret(newObj.(*v1.Secret))
	sw.client.recheckPeerConfig()
}

func (sw *secretWatcher) OnDelete(obj interface{}) {
	log.Debug("Secret deleted")
	sw.deleteSecret(obj.(*v1.Secret))
	sw.client.recheckPeerConfig()
}

func (sw *secretWatcher) updateSecret(secret *v1.Secret) {
	sw.mutex.Lock()
	defer sw.mutex.Unlock()
	sw.watches[secret.Name].secret = secret
}

func (sw *secretWatcher) deleteSecret(secret *v1.Secret) {
	sw.mutex.Lock()
	defer sw.mutex.Unlock()
	delete(sw.watches, secret.Name)
}
