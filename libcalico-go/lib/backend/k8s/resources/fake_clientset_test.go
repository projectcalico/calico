// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package resources

import (
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/testing"
)

// FakeClientSetWithListRevAndFiltering is a fake clientset that plugs a couple
// of gaps in the upstream fake clientset.  Specifically, it allows setting the
// resource version on list responses, and it allows filtering the list response
// based on field selectors.
type FakeClientSetWithListRevAndFiltering struct {
	*fake.Clientset

	DefaultCurrentListRevision string
	CurrentListRevisionByType  map[string]string
}

func NewFakeClientSetWithListRevAndFiltering() *FakeClientSetWithListRevAndFiltering {
	clientset := &FakeClientSetWithListRevAndFiltering{
		Clientset:                  fake.NewSimpleClientset(),
		DefaultCurrentListRevision: "123",
		CurrentListRevisionByType:  map[string]string{},
	}

	reactor := clientset.ReactionChain[0].(*testing.SimpleReactor)
	defaultReaction := reactor.Reaction
	reactor.Reaction = func(action testing.Action) (handled bool, ret runtime.Object, err error) {
		handled, ret, err = defaultReaction(action)
		if action, ok := action.(testing.ListActionImpl); !ok {
			// Not a list, ignore.
			return
		} else if ret, ok := ret.(metav1.ListMetaAccessor); ok {
			// List: set the resource version.
			kind := action.Kind.Kind
			listRev := clientset.CurrentListRevisionByType[kind]
			if listRev == "" {
				listRev = clientset.DefaultCurrentListRevision
			}
			ret.GetListMeta().SetResourceVersion(listRev)
			// Then apply fieldSelector filtering, which is also missing.
			// Using reflection here because generics don't quite have enough
			// power: there's no way to get the Items slice, and we can't
			// do the cast from the slice entry to metav1.ObjectMetaAccessor.
			fieldSelector := action.GetListRestrictions().Fields
			itemsVal := reflect.ValueOf(ret).Elem().FieldByName("Items")
			itemsNew := reflect.MakeSlice(itemsVal.Type(), 0, itemsVal.Len())
			for i := 0; i < itemsVal.Len(); i++ {
				item := itemsVal.Index(i)
				itemPtr := item.Addr().Interface().(metav1.ObjectMetaAccessor)
				meta := itemPtr.GetObjectMeta()
				fieldSet := fields.Set{
					"metadata.name":      meta.GetName(),
					"metadata.namespace": meta.GetNamespace(),
				}
				if fieldSelector.Matches(fieldSet) {
					itemsNew = reflect.Append(itemsNew, item)
				}
			}
			itemsVal.Set(itemsNew)
		}
		return
	}

	return clientset
}
