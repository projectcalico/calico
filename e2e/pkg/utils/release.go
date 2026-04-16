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

package utils

import (
	"context"
	"fmt"
	"os"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	v1 "github.com/tigera/operator/api/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ReleaseStreamIsAtLeast returns true if the RELEASE_STREAM environment
// variable is "master" or is >= the given minimum version. The minVersion
// argument should be in the form "v3.32" (major.minor only, with "v" prefix).
//
// Returns an error if the RELEASE_STREAM environment variable is not set.
func ReleaseStreamIsAtLeast(minVersion string) (bool, error) {
	rs, ok := os.LookupEnv("RELEASE_STREAM")
	if !ok {
		return false, fmt.Errorf("RELEASE_STREAM environment variable is not set")
	}

	if rs == "master" {
		return true, nil
	}

	rsMajor, rsMinor, err := parseVersion(rs)
	if err != nil {
		return false, fmt.Errorf("cannot parse RELEASE_STREAM %q: %w", rs, err)
	}

	minMajor, minMinor, err := parseVersion(minVersion)
	if err != nil {
		return false, fmt.Errorf("invalid minVersion %q: %w", minVersion, err)
	}

	if rsMajor != minMajor {
		return rsMajor > minMajor, nil
	}
	return rsMinor >= minMinor, nil
}

// IsCalicoOSS returns true if the PRODUCT environment variable is "calico".
// Installation isn't probed in-case we are testing a manifest-based installation.
// Container image tags can vary in format, so they are also avoided as a means of version-checking.
func IsCalicoOSS() bool {
	return os.Getenv("PRODUCT") == "calico"
}

// IsCalicoEE returns true if the PRODUCT environment variable is "calico-enterprise".
func IsCalicoEE(ctx context.Context, cli client.Client) (bool, error) {
	installation := &v1.Installation{}
	err := cli.Get(ctx, client.ObjectKey{Name: "default"}, installation)
	if apierrors.IsNotFound(err) {
		// No installation means we're on OSS (manifest installation).
		return false, nil
	}
	// Any other errors should bubble.
	if err != nil {
		return false, err
	}

	if installation.Spec.Variant == v1.TigeraSecureEnterprise {
		return true, nil
	}

	return false, nil
}

// parseVersion parses a "vMAJOR.MINOR" string and returns major, minor.
func parseVersion(v string) (int, int, error) {
	v = strings.TrimPrefix(v, "v")
	var major, minor int
	n, err := fmt.Sscanf(v, "%d.%d", &major, &minor)
	if err != nil || n != 2 {
		return 0, 0, fmt.Errorf("cannot parse version %q", v)
	}
	return major, minor, nil
}
