// Copyright (c) 2023-2024 Tigera, Inc. All rights reserved.

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

package ruleset

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetOWASPCoreRuleSet(t *testing.T) {
	cm, err := GetOWASPCoreRuleSet()
	require.NoError(t, err)
	for _, fileName := range []string{
		"REQUEST-901-INITIALIZATION.conf",
	} {
		_, ok := cm.Data[fileName]
		require.True(t, ok, fmt.Sprintf("file %s not found", fileName))
	}
}

func TestGetWAFRulesetConfig(t *testing.T) {
	cm, err := GetWAFRulesetConfig()
	require.NoError(t, err)
	for _, fileName := range []string{
		"tigera.conf",
		"coraza.conf",
		"crs-setup.conf",
	} {
		_, ok := cm.Data[fileName]
		require.True(t, ok, fmt.Sprintf("file %s not found", fileName))
	}
}
