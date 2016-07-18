// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

package backend

import (
	"reflect"

	"github.com/tigera/libcalico-go/lib/api"
)

// Interface used to calculate a datastore key.
type KeyInterface interface {
	asEtcdKey() (string, error)
	asEtcdDeleteKey() (string, error)
	valueType() reflect.Type
}

// Interface used to perform datastore lookups.
type ListInterface interface {
	asEtcdKeyRoot() string
	keyFromEtcdResult(key string) KeyInterface
}

// Encapsulated datastore key interface with serializable object.
type DatastoreObject struct {
	Key      KeyInterface
	Object   interface{}
	Revision interface{}
}

type DatastoreReadWriteInterface interface {
	Create(object *DatastoreObject) (*DatastoreObject, error)
	Update(object *DatastoreObject) (*DatastoreObject, error)
	Apply(object *DatastoreObject) (*DatastoreObject, error)
	Delete(key KeyInterface) error
	Get(key KeyInterface) (*DatastoreObject, error)
	List(list ListInterface) ([]*DatastoreObject, error)
}

// Backend client data
type Client struct {
	// Calico client config
	config *api.ClientConfig

	// ---- Internal package data ----
	rw DatastoreReadWriteInterface
}

// NewClient creates a new backend datastore client.
func NewClient(config *api.ClientConfig) (*Client, error) {
	c := Client{config: config}

	// Currently backend client is only supported by etcd.
	rw, err := ConnectEtcdClient(config)
	if err != nil {
		return nil, err
	}
	c.rw = rw

	return &c, nil
}

// Create an entry in the datastore.  This errors if the entry already exists.
func (c *Client) Create(d *DatastoreObject) (*DatastoreObject, error) {
	return c.rw.Create(d)
}

// Update an existing entry in the datastore.  This errors if the entry does
// not exist.
func (c *Client) Update(d *DatastoreObject) (*DatastoreObject, error) {
	return c.rw.Update(d)
}

// Set an existing entry in the datastore.  This ignores whether an entry already
// exists.
func (c *Client) Apply(d *DatastoreObject) (*DatastoreObject, error) {
	return c.rw.Apply(d)
}

// Delete an entry in the datastore.  This errors if the entry does not exists.
func (c *Client) Delete(k KeyInterface) error {
	return c.rw.Delete(k)
}

// Get an entry from the datastore.  This errors if the entry does not exist.
func (c *Client) Get(k KeyInterface) (*DatastoreObject, error) {
	return c.rw.Get(k)
}

// List entries in the datastore.  This may return an empty list of there are
// no entries matching the request in the ListInterface.
func (c *Client) List(l ListInterface) ([]*DatastoreObject, error) {
	return c.rw.List(l)
}
