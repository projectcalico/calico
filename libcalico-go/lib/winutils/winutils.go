// Copyright (c) 2023 Tigera, Inc. All rights reserved.
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
package winutils

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func Powershell(args ...string) (string, string, error) {
	// Add default powershell to PATH
	path := os.Getenv("PATH")
	err := os.Setenv("PATH", path+";C:/Windows/System32/WindowsPowerShell/v1.0/")
	if err != nil {
		return "", "", err
	}

	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		return "", "", err
	}

	args = append([]string{"-NoProfile", "-NonInteractive"}, args...)
	cmd := exec.Command(ps, args...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		return "", "", err
	}

	return stdout.String(), stderr.String(), err
}

// GetHostPath returns the mount paths for a container
// In the case of Windows HostProcess containers this prepends the CONTAINER_SANDBOX_MOUNT_POINT env variable
// for other operating systems or if the sandbox env variable is not set it returns the standard mount points
// see https://kubernetes.io/docs/tasks/configure-pod-container/create-hostprocess-pod/#volume-mounts
// FIXME: this will no longer be needed when containerd v1.6 is EOL'd
func GetHostPath(path string) string {
	if runtime.GOOS == "windows" {
		sandbox := os.Getenv("CONTAINER_SANDBOX_MOUNT_POINT")
		// join them and return with forward slashes so it can be serialized properly in json later if required
		path := strings.TrimLeft(path, "c:")
		path = strings.TrimLeft(path, "C:")
		path = filepath.Join(sandbox, path, "c:")
		return filepath.ToSlash(path)
	}
	return path
}
