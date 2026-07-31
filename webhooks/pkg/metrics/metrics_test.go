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

package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterAllIsIdempotentPerRegistry(t *testing.T) {
	registry := prometheus.NewRegistry()
	require.NoError(t, RegisterAll(registry))

	// A second registration into the same registry must not panic or error, so that a
	// restart-in-place or a test that registers twice does not take the process down.
	assert.NoError(t, RegisterAll(registry))
}

func TestDecisionsTotalCounts(t *testing.T) {
	DecisionsTotal.Reset()
	DecisionsTotal.WithLabelValues("denied", "networkpolicies", "list").Inc()

	assert.Equal(t, 1.0, testutil.ToFloat64(DecisionsTotal.WithLabelValues("denied", "networkpolicies", "list")))
}
