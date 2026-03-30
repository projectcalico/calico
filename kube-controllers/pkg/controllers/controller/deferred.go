// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
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

package controller

import (
	"context"

	"github.com/sirupsen/logrus"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apiextinformers "k8s.io/apiextensions-apiserver/pkg/client/informers/externalversions"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/lib/std/chanutil"
)

// DeferredCRDController implements Controller by watching for a CRD to become
// Established before starting the inner controller. If the CRD is removed, the
// inner controller's context is cancelled. If the CRD is recreated, the inner
// controller is started again.
type DeferredCRDController interface {
	Controller
}

// ContextController is a controller whose lifecycle is driven by a context.
// Used with DeferredCRDController — the provided context is cancelled when
// the CRD is removed or the parent controller is stopped.
type ContextController interface {
	RunWithContext(ctx context.Context)
}

// NewDeferredCRDController creates a Controller that waits for the named CRD to
// become Established before calling inner.RunWithContext. The inner controller's
// context is cancelled if the CRD is deleted.
func NewDeferredCRDController(crdName string, crdClient apiextclient.Interface, inner ContextController) DeferredCRDController {
	return &deferredCRDController{
		crdName:   crdName,
		crdClient: crdClient,
		inner:     inner,
	}
}

type deferredCRDController struct {
	crdName   string
	crdClient apiextclient.Interface
	inner     ContextController
}

func (d *deferredCRDController) Run(stop chan struct{}) {
	logCtx := logrus.WithField("crd", d.crdName)
	logCtx.Info("Waiting for CRD to become established")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-stop
		cancel()
	}()

	factory := apiextinformers.NewSharedInformerFactory(d.crdClient, 0)
	informer := factory.Apiextensions().V1().CustomResourceDefinitions().Informer()

	// readyCh is signalled (from informer goroutines) when the CRD becomes
	// Established. deletedCh is signalled when the CRD is removed. stoppedCh
	// is signalled when the inner controller's RunWithContext returns. All
	// three feed into the select loop below, which is the only place that
	// touches innerCancel — avoiding data races.
	readyCh := make(chan struct{}, 1)
	deletedCh := make(chan struct{}, 1)
	stoppedCh := make(chan struct{}, 1)

	var innerCancel context.CancelFunc

	handler := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			crd, ok := obj.(*apiextv1.CustomResourceDefinition)
			if !ok || crd.Name != d.crdName {
				return
			}
			if isCRDEstablished(crd) {
				logCtx.Info("CRD is established")
				chanutil.WriteNonBlocking(readyCh, struct{}{})
			}
		},
		UpdateFunc: func(_, newObj any) {
			crd, ok := newObj.(*apiextv1.CustomResourceDefinition)
			if !ok || crd.Name != d.crdName {
				return
			}
			if isCRDEstablished(crd) {
				chanutil.WriteNonBlocking(readyCh, struct{}{})
			}
		},
		DeleteFunc: func(obj any) {
			crd, ok := obj.(*apiextv1.CustomResourceDefinition)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					return
				}
				crd, ok = tombstone.Obj.(*apiextv1.CustomResourceDefinition)
				if !ok {
					return
				}
			}
			if crd.Name != d.crdName {
				return
			}
			logCtx.Info("CRD was deleted, stopping inner controller")
			chanutil.WriteNonBlocking(deletedCh, struct{}{})
		},
	}

	if _, err := informer.AddEventHandler(handler); err != nil {
		logCtx.WithError(err).Error("Failed to add CRD event handler")
		return
	}

	go informer.Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		logCtx.Error("Failed to sync CRD informer cache")
		return
	}

	for {
		select {
		case <-ctx.Done():
			if innerCancel != nil {
				innerCancel()
			}
			return

		case <-readyCh:
			if innerCancel != nil {
				continue
			}
			var innerCtx context.Context
			innerCtx, innerCancel = context.WithCancel(ctx)
			go func() {
				d.inner.RunWithContext(innerCtx)
				chanutil.WriteNonBlocking(stoppedCh, struct{}{})
			}()

		case <-deletedCh:
			if innerCancel != nil {
				innerCancel()
				innerCancel = nil
			}

		case <-stoppedCh:
			innerCancel = nil
		}
	}
}

func isCRDEstablished(crd *apiextv1.CustomResourceDefinition) bool {
	for _, c := range crd.Status.Conditions {
		if c.Type == apiextv1.Established && c.Status == apiextv1.ConditionTrue {
			return true
		}
	}
	return false
}
