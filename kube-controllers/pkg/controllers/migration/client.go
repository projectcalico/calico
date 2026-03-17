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

package migration

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
)

// migrationClient is a typed wrapper around the dynamic client for DatastoreMigration resources.
// It handles conversion between typed and unstructured representations.
type migrationClient struct {
	client dynamic.Interface
}

func newMigrationClient(client dynamic.Interface) *migrationClient {
	return &migrationClient{client: client}
}

// Get retrieves a DatastoreMigration by name.
func (c *migrationClient) Get(ctx context.Context, name string) (*DatastoreMigration, error) {
	uns, err := c.client.Resource(DatastoreMigrationGVR).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return fromUnstructured(uns)
}

// UpdateStatus updates the status subresource and returns the updated object.
func (c *migrationClient) UpdateStatus(ctx context.Context, dm *DatastoreMigration) (*DatastoreMigration, error) {
	uns, err := toUnstructured(dm)
	if err != nil {
		return nil, fmt.Errorf("converting to unstructured: %w", err)
	}
	updated, err := c.client.Resource(DatastoreMigrationGVR).UpdateStatus(ctx, uns, metav1.UpdateOptions{})
	if err != nil {
		return nil, err
	}
	return fromUnstructured(updated)
}

// Update updates the metadata (annotations, finalizers, labels) of a DatastoreMigration.
func (c *migrationClient) Update(ctx context.Context, dm *DatastoreMigration) (*DatastoreMigration, error) {
	uns, err := toUnstructured(dm)
	if err != nil {
		return nil, fmt.Errorf("converting to unstructured: %w", err)
	}
	updated, err := c.client.Resource(DatastoreMigrationGVR).Update(ctx, uns, metav1.UpdateOptions{})
	if err != nil {
		return nil, err
	}
	return fromUnstructured(updated)
}

func fromUnstructured(uns *unstructured.Unstructured) (*DatastoreMigration, error) {
	dm := &DatastoreMigration{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(uns.Object, dm); err != nil {
		return nil, fmt.Errorf("converting from unstructured: %w", err)
	}
	return dm, nil
}

func toUnstructured(dm *DatastoreMigration) (*unstructured.Unstructured, error) {
	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(dm)
	if err != nil {
		return nil, fmt.Errorf("converting to unstructured: %w", err)
	}
	return &unstructured.Unstructured{Object: obj}, nil
}
