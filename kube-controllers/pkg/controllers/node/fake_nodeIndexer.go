// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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
package node

import (
	"context"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// fakeNodeIndexer is a type for testing that implements cache.Indexer and passes requests directly to a kubernetes client.
type fakeNodeIndexer struct {
	cs kubernetes.Interface
}

func newFakeNodeIndexer(cs kubernetes.Interface) fakeNodeIndexer {
	return fakeNodeIndexer{
		cs: cs,
	}
}

func (f fakeNodeIndexer) Add(obj interface{}) error {
	panic("not implemented")
}

func (f fakeNodeIndexer) Update(obj interface{}) error {
	panic("not implemented")
}

func (f fakeNodeIndexer) Delete(obj interface{}) error {
	panic("not implemented")
}

func (f fakeNodeIndexer) List() []interface{} {
	panic("not implemented")
}

func (f fakeNodeIndexer) ListKeys() []string {
	panic("not implemented")
}

func (f fakeNodeIndexer) Get(obj interface{}) (item interface{}, exists bool, err error) {
	panic("not implemented")
}

func (f fakeNodeIndexer) GetByKey(key string) (item interface{}, exists bool, err error) {
	get, err := f.cs.CoreV1().Nodes().Get(context.TODO(), key, metav1.GetOptions{})
	if err != nil {
		return nil, false, err
	}
	return get, true, nil
}

func (f fakeNodeIndexer) Replace(i []interface{}, s string) error {
	panic("not implemented")
}

func (f fakeNodeIndexer) Resync() error {
	panic("not implemented")
}

func (f fakeNodeIndexer) Index(indexName string, obj interface{}) ([]interface{}, error) {
	panic("not implemented")
}

func (f fakeNodeIndexer) IndexKeys(indexName, indexedValue string) ([]string, error) {
	panic("not implemented")
}

func (f fakeNodeIndexer) ListIndexFuncValues(indexName string) []string {
	panic("not implemented")
}

func (f fakeNodeIndexer) ByIndex(indexName, indexedValue string) ([]interface{}, error) {
	panic("not implemented")
}

func (f fakeNodeIndexer) GetIndexers() cache.Indexers {
	panic("not implemented")
}

func (f fakeNodeIndexer) AddIndexers(newIndexers cache.Indexers) error {
	panic("not implemented")
}
