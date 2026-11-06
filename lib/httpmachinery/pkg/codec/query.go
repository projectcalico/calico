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

package codec

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"sync"
)

// queryParamNameCache holds the accept list per params type, so the reflection
// runs once rather than on every request.
var queryParamNameCache sync.Map

// QueryParamNames lists the urlQuery parameters T declares, following ",inline"
// embedded structs. A route's accept list is derived from its params type
// rather than kept in step with it by hand.
func QueryParamNames[T any]() map[string]struct{} {
	var zero T
	t := reflect.TypeOf(zero)
	if t == nil || t.Kind() != reflect.Struct {
		return map[string]struct{}{}
	}
	if cached, ok := queryParamNameCache.Load(t); ok {
		return maps.Clone(cached.(map[string]struct{}))
	}

	names := make(map[string]struct{})
	var walk func(reflect.Type)
	walk = func(t reflect.Type) {
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			tag, ok := field.Tag.Lookup(tagURLQuery)
			if !ok {
				continue
			}
			name, opts, _ := strings.Cut(tag, ",")
			if name == "" && slices.Contains(strings.Split(opts, ","), "inline") && field.Type.Kind() == reflect.Struct {
				walk(field.Type)
				continue
			}
			if name != "" && name != "-" {
				names[name] = struct{}{}
			}
		}
	}
	walk(t)

	queryParamNameCache.Store(t, names)
	return maps.Clone(names)
}

// rejectUnknownQueryParameters fails when the query carries a parameter the
// params type does not declare. url.Values keeps such a parameter, and decoding
// silently ignores it, so a misspelt filter would otherwise answer 200 with the
// filter not applied.
func rejectUnknownQueryParameters(allowed map[string]struct{}, query map[string][]string) error {
	for key := range query {
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("unknown query parameter %q", key)
		}
	}
	return nil
}
