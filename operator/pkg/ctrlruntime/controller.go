// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

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

// The runtime package contains implementations / extensions to the controller runtime package, allowing us to use the
// intermediate interfaces we define to easily modify and extend the functionality of the runtime package to our needs,
// without exposing the details.
//
// Future additions to this package might include tooling to help with cache management, specifically reducing the size
// of the cache through specific dynamic namespace caching.

package ctrlruntime

import (
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// Controller implements and extends the controller.Controller interface. Implementations should store the cache from the
// manager the controller is made from so the WatchObject function can be implemented.
//
// This adaptation of the controller.Controller interface is needed mainly because we follow a slightly different flow from
// the standard operator flow, where we add watches after the controller has been created (watches for objects that rely
// on the API Server that's created by the operator).
//
// The controller.Controller interface now requires using a cache to set up the watches, while the ctrl.Builder interface
// is tailored to creating watches before the manager / controller has been started.
type Controller interface {
	controller.Controller

	// WatchObject creates a watch for the specific object, using the cache stored internal to the Controller.
	WatchObject(object client.Object, eventhandler handler.EventHandler, predicates ...predicate.Predicate) error

	// WatchObjectInCache creates a watch for the specific object using the
	// provided cache instead of the manager's shared cache. Use this when a
	// controller needs a scoped (e.g. label-filtered) informer for a type so
	// it does not force the manager's shared cache to list/watch every object
	// of that type cluster-wide.
	WatchObjectInCache(cch cache.Cache, object client.Object, eventhandler handler.EventHandler, predicates ...predicate.Predicate) error
}

// controler is an implementation of Controller. It stores the cache from the manager it was created from and uses it
// to create the watches needed for the object provided to the WatchObject function.
type controler struct {
	controller.Controller
	cach cache.Cache
}

func NewController(name string, mgr manager.Manager, options controller.Options) (Controller, error) {
	c, err := controller.New(name, mgr, options)
	if err != nil {
		return nil, err
	}

	return &controler{Controller: c, cach: mgr.GetCache()}, nil
}

func (c *controler) WatchObject(object client.Object, eventhandler handler.EventHandler, predicates ...predicate.Predicate) error {
	return c.Watch(source.Kind(c.cach, object, eventhandler, predicates...))
}

func (c *controler) WatchObjectInCache(cch cache.Cache, object client.Object, eventhandler handler.EventHandler, predicates ...predicate.Predicate) error {
	return c.Watch(source.Kind(cch, object, eventhandler, predicates...))
}
