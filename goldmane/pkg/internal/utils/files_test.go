// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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
package utils_test

import (
	"context"
	"os"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/goldmane/pkg/internal/utils"
	"github.com/projectcalico/calico/lib/std/time"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

func TestFileWatcher(t *testing.T) {
	RegisterTestingT(t)
	utils.ConfigureLogging("DEBUG")
	defer logutils.RedirectLogrusToTestingT(t)()

	// Create a tmp file to watch.
	dir := os.TempDir()
	f, err := os.CreateTemp(dir, "testfile")
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	// Create a file watcher.
	updChan := make(chan struct{}, 1)
	watchFn, err := utils.WatchFilesFn(updChan, 250*time.Millisecond, f.Name())
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go watchFn(ctx)

	Consistently(updChan, 1*time.Second, 10*time.Millisecond).ShouldNot(Receive())

	// Write to the file, triggering an update.
	_, err = f.WriteString("test")
	require.NoError(t, err)

	Eventually(updChan, 5*time.Second, 10*time.Millisecond).Should(Receive())
	Consistently(updChan, 1*time.Second, 10*time.Millisecond).ShouldNot(Receive())

	// Write to the file again, triggering another update.
	_, err = f.WriteString("test")
	require.NoError(t, err)

	Eventually(updChan, 5*time.Second, 10*time.Millisecond).Should(Receive())

	// Delete the file. We should get an update.
	err = os.Remove(f.Name())
	require.NoError(t, err)

	Eventually(updChan, 5*time.Second, 10*time.Millisecond).Should(Receive())

	// Recreate the file. We should get an update.
	f2, err := os.Create(f.Name())
	require.NoError(t, err)
	defer func() { _ = f2.Close() }()
	_, err = f2.WriteString("test")
	require.NoError(t, err)
	Eventually(updChan, 5*time.Second, 10*time.Millisecond).Should(Receive())
}
