// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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

package utils

import (
	"sync"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type objectAndKind struct {
	Object client.ObjectKey
	Kind   schema.GroupKind
}

type objectCache struct {
	sync.Mutex
	generations map[objectAndKind]int64
	objects     map[objectAndKind]client.Object
}

func newCache() *objectCache {
	return &objectCache{
		generations: make(map[objectAndKind]int64),
		objects:     make(map[objectAndKind]client.Object),
	}
}

func (c *objectCache) set(obj client.Object, generation int64) {
	c.Lock()
	defer c.Unlock()

	// Update the caches so that we don't try to update the object on subsequent reconciliations.
	c.generations[c.key(obj)] = generation
	c.objects[c.key(obj)] = obj
}

// get retrieves an object from the cache, returning the object, its generation, and a boolean indicating
// whether the object was found in the cache.
func (c *objectCache) get(obj client.Object) (client.Object, int64, bool) {
	c.Lock()
	defer c.Unlock()

	key := c.key(obj)
	if cachedObj, ok := c.objects[key]; ok {
		return cachedObj, c.generations[key], true
	}
	return nil, 0, false
}

func (d *objectCache) delete(obj client.Object) {
	d.Lock()
	defer d.Unlock()

	key := d.key(obj)
	delete(d.generations, key)
	delete(d.objects, key)
}

func (c *objectCache) key(obj client.Object) objectAndKind {
	return objectAndKind{
		Object: client.ObjectKeyFromObject(obj),
		Kind:   obj.GetObjectKind().GroupVersionKind().GroupKind(),
	}
}
