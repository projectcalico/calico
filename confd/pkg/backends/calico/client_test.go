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
package calico

import (
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestKeyUpdated_LogLevel(t *testing.T) {
	const nodeLogKey = "/calico/bgp/v1/host/node1/loglevel"

	tests := []struct {
		name              string
		revisionsByPrefix map[string]uint64
		cache             map[string]string
		key               string
		expectedLevel     log.Level
	}{
		{
			// The stock templates no longer watch /calico/bgp/v1/global, but confd should
			// still follow the global log level.
			name: "global log level, no watched prefix covers the key",
			revisionsByPrefix: map[string]uint64{
				"/calico/bgpconfig":   0,
				"/calico/bgp/v1/host": 0,
			},
			cache:         map[string]string{globalLogging: "debug"},
			key:           globalLogging,
			expectedLevel: log.DebugLevel,
		},
		{
			// An earlier key in the same batch, e.g. listen_port from the same per-node
			// BGPConfiguration, has already bumped the prefix covering the log level key.
			name: "node log level, covering prefix already bumped in this batch",
			revisionsByPrefix: map[string]uint64{
				"/calico/bgp/v1/host": 7,
			},
			cache:         map[string]string{nodeLogKey: "warning"},
			key:           nodeLogKey,
			expectedLevel: log.WarnLevel,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("BGP_LOGSEVERITYSCREEN", "")
			origLevel := log.GetLevel()
			defer log.SetLevel(origLevel)
			log.SetLevel(log.InfoLevel)

			c := &client{
				cache:             tt.cache,
				revisionsByPrefix: tt.revisionsByPrefix,
				cacheRevision:     7,
				nodeLogKey:        nodeLogKey,
			}
			c.keyUpdated(tt.key)

			assert.Equal(t, tt.expectedLevel, log.GetLevel())
		})
	}
}
