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

// openapi-schema dumps the Calico OpenAPI schema as Swagger 2.0 JSON to stdout.
// The output is consumed by applyconfiguration-gen --openapi-schema to populate
// the structured-merge-diff type information needed by fake.NewClientset().
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/projectcalico/api/pkg/openapi"
	"k8s.io/kube-openapi/pkg/util"
	"k8s.io/kube-openapi/pkg/validation/spec"
)

// sanitizeForSwagger2 removes OpenAPI 3.0 fields (like oneOf) that are not
// valid in Swagger 2.0 and cause the gnostic parser to reject the document.
func sanitizeForSwagger2(defs spec.Definitions) {
	for name, schema := range defs {
		schema.OneOf = nil
		schema.AnyOf = nil
		defs[name] = schema
	}
}

// toFriendlyName converts a Go type name to REST-friendly format if needed.
// Keys from OpenAPIModelName() are already REST-friendly (no "/" in them).
// Keys that are raw Go package paths (contain "/") need conversion.
func toFriendlyName(name string) string {
	if strings.Contains(name, "/") {
		return util.ToRESTFriendlyName(name)
	}
	return name
}

func main() {
	// Build a $ref callback that produces REST-friendly $ref paths.
	refFunc := func(path string) spec.Ref {
		friendlyName := toFriendlyName(path)
		ref, _ := spec.NewRef("#/definitions/" + friendlyName)
		return ref
	}

	// Get all OpenAPI definitions (Calico + transitive k8s dependencies).
	allDefs := openapi.GetOpenAPIDefinitions(refFunc)

	// Build Swagger definitions map with REST-friendly names.
	definitions := spec.Definitions{}
	for goType, def := range allDefs {
		friendlyName := toFriendlyName(goType)
		definitions[friendlyName] = def.Schema
	}

	sanitizeForSwagger2(definitions)

	swagger := &spec.Swagger{
		SwaggerProps: spec.SwaggerProps{
			Swagger: "2.0",
			Info: &spec.Info{
				InfoProps: spec.InfoProps{
					Title:   "Calico API",
					Version: "v3",
				},
			},
			Paths:       &spec.Paths{},
			Definitions: definitions,
		},
	}

	data, err := json.MarshalIndent(swagger, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal schema: %v\n", err)
		os.Exit(1)
	}

	_, err = os.Stdout.Write(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write: %v\n", err)
		os.Exit(1)
	}
}
