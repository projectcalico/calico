// Copyright (c) 2024,2026 Tigera, Inc. All rights reserved.

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

package client

import (
	"reflect"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TypesWithStatuses(scheme *runtime.Scheme, groupVersions ...schema.GroupVersion) []client.Object {
	types := scheme.AllKnownTypes()
	var statusObjects []client.Object

	gvMap := map[schema.GroupVersion]struct{}{}
	for _, gv := range groupVersions {
		gvMap[gv] = struct{}{}
	}

	for gvk, typeInfo := range types {
		if _, ok := gvMap[gvk.GroupVersion()]; !ok {
			continue
		}

		_, ok := typeInfo.FieldByName("Status")
		if ok {
			value := reflect.Indirect(reflect.New(typeInfo))
			var obj any
			if typeInfo.Kind() == reflect.Pointer {
				obj = value.Interface()
			} else {
				if !value.CanAddr() {
					continue
				}
				obj = value.Addr().Interface()
			}

			if cliObj, ok := obj.(client.Object); ok {
				statusObjects = append(statusObjects, cliObj)
			}
		}
	}

	return statusObjects
}
