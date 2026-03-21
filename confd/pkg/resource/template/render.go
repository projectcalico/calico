// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package template

import (
	"bytes"
	"fmt"
	"path/filepath"
	"text/template"

	"github.com/kelseyhightower/memkv"

	"github.com/projectcalico/calico/confd/pkg/backends"
)

// RenderTemplate renders a confd template file using the provided StoreClient and KV data.
// templatePath is the full path to the .template file.
// client provides getBGPConfig and is passed as the template dot context.
// kvData populates the memkv store used by template functions like ls, gets, getv, exists.
func RenderTemplate(templatePath string, client backends.StoreClient, kvData map[string]string) (string, error) {
	store := memkv.New()
	for k, v := range kvData {
		store.Set(k, v)
	}

	funcMap := newFuncMap()
	addFuncs(funcMap, store.FuncMap)
	addCalicoFuncs(funcMap)

	tmpl, err := template.New(filepath.Base(templatePath)).Funcs(funcMap).ParseFiles(templatePath)
	if err != nil {
		return "", fmt.Errorf("parsing template %s: %w", templatePath, err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, client); err != nil {
		return "", fmt.Errorf("executing template %s: %w", templatePath, err)
	}
	return buf.String(), nil
}
