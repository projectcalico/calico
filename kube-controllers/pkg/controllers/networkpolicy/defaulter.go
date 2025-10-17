// Copyright (c) 2017-2024 Tigera, Inc. All rights reserved.
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

package networkpolicy

import (
	"context"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/client/clientset_generated/clientset"
	"github.com/projectcalico/api/pkg/defaults"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/controller"
)

func NewPolicyDefaulter(
	ctx context.Context,
	cli clientset.Interface,
	gnps cache.SharedIndexInformer,
	nps cache.SharedIndexInformer,
) controller.Controller {
	d := &policyDefaulter{
		ctx:      ctx,
		cli:      cli,
		informer: gnps,
	}

	// Register for reconcile calls.
	funcs := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			d.Mux(obj)
		},
		UpdateFunc: func(oldObj, newObj any) {
			d.Mux(newObj)
		},
	}
	if _, err := gnps.AddEventHandler(funcs); err != nil {
		logrus.WithError(err).Fatal("Failed to register event handler for GlobalNetworkPolicies")
	}
	if _, err := nps.AddEventHandler(funcs); err != nil {
		logrus.WithError(err).Fatal("Failed to register event handler for NetworkPolicies")
	}

	return d
}

type policyDefaulter struct {
	ctx      context.Context
	cli      clientset.Interface
	informer cache.SharedIndexInformer
}

func (c *policyDefaulter) Run(stopCh chan struct{}) {
	defer uruntime.HandleCrash()

	logrus.Info("Starting NetworkPolicy defaulting controller")

	// Wait till k8s cache is synced
	logrus.Debug("Waiting to sync with Kubernetes API (NetworkPolicy defaulting)")
	if !cache.WaitForNamedCacheSync("pools", stopCh, c.informer.HasSynced) {
		logrus.Info("Failed to sync resources, received signal for controller to shut down.")
		return
	}

	logrus.Debug("Finished syncing with Kubernetes API (NetworkPolicy defaulting)")

	// We're in-sync. Start the sub-controllers.
	<-stopCh
	logrus.Info("Stopping NetworkPolicy defaulting controller")
}

func (c *policyDefaulter) Mux(obj any) {
	switch t := obj.(type) {
	case *v3.GlobalNetworkPolicy:
		if err := c.defaultGlobalNetworkPolicy(t); err != nil {
			logrus.Errorf("Failed to reconcile GlobalNetworkPolicy %s: %v", t.Name, err)
		}
	case *v3.NetworkPolicy:
		if err := c.defaultNetworkPolicy(t); err != nil {
			logrus.Errorf("Failed to reconcile NetworkPolicy %s/%s: %v", t.Namespace, t.Name, err)
		}
	default:
		logrus.Errorf("Received unexpected object: %v", obj)
	}
}

func (c *policyDefaulter) defaultNetworkPolicy(p *v3.NetworkPolicy) error {
	changed, err := defaults.Default(p)
	if err != nil {
		logrus.WithError(err).Errorf("Failed to default NetworkPolicy %s/%s", p.Namespace, p.Name)
		return err
	} else if !changed {
		// No change, nothing to do.
		return nil
	}

	// Update the policy.
	_, err = c.cli.ProjectcalicoV3().NetworkPolicies(p.Namespace).Update(c.ctx, p, v1.UpdateOptions{})
	if err != nil {
		logrus.WithError(err).Errorf("Failed to update NetworkPolicy %s/%s", p.Namespace, p.Name)
		return err
	}
	return nil
}

func (c *policyDefaulter) defaultGlobalNetworkPolicy(p *v3.GlobalNetworkPolicy) error {
	changed, err := defaults.Default(p)
	if err != nil {
		logrus.WithError(err).Errorf("Failed to default GlobalNetworkPolicy %s", p.Name)
		return err
	} else if !changed {
		// No change, nothing to do.
		return nil
	}

	// Update the policy.
	_, err = c.cli.ProjectcalicoV3().GlobalNetworkPolicies().Update(c.ctx, p, v1.UpdateOptions{})
	if err != nil {
		logrus.WithError(err).Errorf("Failed to update GlobalNetworkPolicy %s", p.Name)
		return err
	}
	return nil
}
