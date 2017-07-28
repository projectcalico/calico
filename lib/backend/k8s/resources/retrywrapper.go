// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package resources

import (
	"github.com/projectcalico/libcalico-go/lib/backend/model"

	log "github.com/sirupsen/logrus"
)

const (
	maxActionRetries = 5
)

// retryWrapper implements the K8sResourceClient interface and is used to wrap
// another K8sResourceClient to provide retry functionality when the failure
// case is of type retryError.
type retryWrapper struct {
	client K8sResourceClient
}

// retryError is an error type used to indicate to the retryWrapper to retry
// a specific action.
//
// If the action is retried the max number of times, then the retryWrapper will
// return the underlying error.
type retryError struct {
	err error
}

func (r retryError) Error() string {
	return r.err.Error()
}

func (r *retryWrapper) Create(object *model.KVPair) (*model.KVPair, error) {
	var kvp *model.KVPair
	var err error
	for i := 0; i < maxActionRetries; i++ {
		if kvp, err = r.client.Create(object); err == nil {
			// No error, exit returning the KVPair.
			return kvp, nil
		} else {
			return nil, err
		}
	}

	// Excessive retries.  Return the last error.
	log.WithField("Key", object.Key).Warning("Failed to create object: too many retries")
	return nil, err.(retryError).err
}

func (r *retryWrapper) Update(object *model.KVPair) (*model.KVPair, error) {
	var kvp *model.KVPair
	var err error
	for i := 0; i < maxActionRetries; i++ {
		if kvp, err = r.client.Update(object); err == nil {
			// No error, exit returning the KVPair.
			return kvp, nil
		} else if _, ok := err.(retryError); !ok {
			return nil, err
		}
	}

	// Excessive retries.  Return the last error.
	log.WithField("Key", object.Key).Error("Failed to update object: too many retries")
	return nil, err.(retryError).err
}

func (r *retryWrapper) Apply(object *model.KVPair) (*model.KVPair, error) {
	var kvp *model.KVPair
	var err error
	for i := 0; i < maxActionRetries; i++ {
		if kvp, err = r.client.Apply(object); err == nil {
			// No error, exit returning the KVPair.
			return kvp, nil
		} else if _, ok := err.(retryError); !ok {
			return nil, err
		}
	}

	// Excessive retries.  Return the last error.
	log.WithField("Key", object.Key).Error("Failed to apply object: too many retries")
	return nil, err.(retryError).err
}

func (r *retryWrapper) Delete(object *model.KVPair) error {
	var err error
	for i := 0; i < maxActionRetries; i++ {
		if err = r.client.Delete(object); err == nil {
			// No error, exit returning the KVPair.
			return nil
		} else if _, ok := err.(retryError); !ok {
			return err
		}
	}

	// Excessive retries.  Return the last error.
	log.WithField("Key", object.Key).Error("Failed to delete object: too many retries")
	return err.(retryError).err
}

func (r *retryWrapper) Get(key model.Key) (*model.KVPair, error) {
	var kvp *model.KVPair
	var err error
	for i := 0; i < maxActionRetries; i++ {
		if kvp, err = r.client.Get(key); err == nil {
			// No error, exit returning the KVPair.
			return kvp, nil
		} else if _, ok := err.(retryError); !ok {
			return nil, err
		}
	}

	// Excessive retries.  Return the last error.
	log.WithField("Key", key).Error("Failed to get object: too many retries")
	return nil, err.(retryError).err
}

func (r *retryWrapper) List(list model.ListInterface) ([]*model.KVPair, string, error) {
	var rev string
	var kvps []*model.KVPair
	var err error
	for i := 0; i < maxActionRetries; i++ {
		if kvps, rev, err = r.client.List(list); err == nil {
			// No error, exit returning the KVPair.
			return kvps, rev, nil
		} else if _, ok := err.(retryError); !ok {
			return nil, "", err
		}
	}

	// Excessive retries.  Return the last error.
	log.WithField("List", list).Error("Failed to list object: too many retries")
	return nil, "", err.(retryError).err
}

func (r *retryWrapper) EnsureInitialized() error {
	var err error
	for i := 0; i < maxActionRetries; i++ {
		if err = r.client.EnsureInitialized(); err == nil {
			// No error, exit returning the KVPair.
			return nil
		} else if _, ok := err.(retryError); !ok {
			return err
		}
	}

	// Excessive retries.  Return the last error.
	log.Error("Failed to initialize: too many retries")
	return err.(retryError).err
}
