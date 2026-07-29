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

package calicoclient

import (
	"errors"
	"testing"
	"time"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

// unreachable is the error the etcdv3 backend returns when it cannot reach the
// datastore while building the client.
var unreachable = cerrors.ErrorDatastoreError{Err: errors.New("context deadline exceeded")}

func TestCreateClientRetriesUnreachableDatastoreWhenWaiting(t *testing.T) {
	attempts := 0
	newClient := func(apiconfig.CalicoAPIConfig) (client.Interface, error) {
		attempts++
		if attempts < 3 {
			return nil, unreachable
		}
		return client.NewFromBackend(apiconfig.CalicoAPIConfig{}, nil), nil
	}

	slept := 0
	c, err := createClient(&apiconfig.CalicoAPIConfig{}, true, newClient, func(time.Duration) { slept++ })
	if err != nil {
		t.Fatalf("expected the client to be created once the datastore came up, got %v", err)
	}
	if c == nil {
		t.Fatal("expected a client")
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
	if slept != 2 {
		t.Errorf("expected to wait between attempts, slept %d times", slept)
	}
}

func TestCreateClientDoesNotRetryWhenNotWaiting(t *testing.T) {
	attempts := 0
	newClient := func(apiconfig.CalicoAPIConfig) (client.Interface, error) {
		attempts++
		return nil, unreachable
	}

	_, err := createClient(&apiconfig.CalicoAPIConfig{}, false, newClient, func(time.Duration) {
		t.Error("should not have waited when WAIT_FOR_DATASTORE is unset")
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	if attempts != 1 {
		t.Errorf("expected a single attempt, got %d", attempts)
	}
}

func TestCreateClientDoesNotRetryConfigErrors(t *testing.T) {
	// A bad configuration will not fix itself, so waiting on it would hang
	// startup forever.
	configErr := errors.New("no etcd endpoints specified")

	attempts := 0
	newClient := func(apiconfig.CalicoAPIConfig) (client.Interface, error) {
		attempts++
		return nil, configErr
	}

	_, err := createClient(&apiconfig.CalicoAPIConfig{}, true, newClient, func(time.Duration) {
		t.Error("should not have waited on a configuration error")
	})
	if !errors.Is(err, configErr) {
		t.Fatalf("expected the configuration error to be returned, got %v", err)
	}
	if attempts != 1 {
		t.Errorf("expected a single attempt, got %d", attempts)
	}
}
