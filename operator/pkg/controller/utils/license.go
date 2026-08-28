// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/tigera/operator/pkg/ctrlruntime"
)

// LicenseStatus represents the current state of the license with respect to expiry and grace period.
type LicenseStatus int

const (
	// LicenseStatusValid means the license has not expired.
	LicenseStatusValid LicenseStatus = iota
	// LicenseStatusInGracePeriod means the license expiry has passed but the grace period has not elapsed.
	LicenseStatusInGracePeriod
	// LicenseStatusExpired means the license expiry plus the grace period has passed.
	LicenseStatusExpired
)

// WaitToAddLicenseKeyWatch starts a goroutine that waits for the LicenseKey CRD to be available
// and then adds a watch for it on the given controller.
func WaitToAddLicenseKeyWatch(controller ctrlruntime.Controller, c kubernetes.Interface, log logr.Logger, flag *ReadyFlag) {
	WaitToAddResourceWatch(controller, c, log, flag, []client.Object{&v3.LicenseKey{TypeMeta: metav1.TypeMeta{Kind: v3.KindLicenseKey}}})
}

// FetchLicenseKey returns the license if it has been installed. It's useful
// to prevent rollout of enterprise components that might require it.
// It will return an error if the license is not installed/cannot be read
func FetchLicenseKey(ctx context.Context, cli client.Client) (v3.LicenseKey, error) {
	instance := &v3.LicenseKey{}
	err := cli.Get(ctx, DefaultInstanceKey, instance)
	return *instance, err
}

// IsFeatureActive return true if the feature is listed in LicenseStatusKey
func IsFeatureActive(license v3.LicenseKey, featureName string) bool {
	for _, v := range license.Status.Features {
		if v == featureName || v == "all" {
			return true
		}
	}

	return false
}

// ParseGracePeriod parses a grace period string in the format "Nd" (e.g. "90d")
// where N is a non-negative number of days. This is the format produced by the
// license controller. Returns 0 if the string is empty, cannot be parsed, or
// represents a negative duration.
func ParseGracePeriod(gracePeriod string) time.Duration {
	if gracePeriod == "" {
		return 0
	}
	s, ok := strings.CutSuffix(gracePeriod, "d")
	if !ok {
		return 0
	}
	days, err := strconv.Atoi(s)
	if err != nil || days < 0 {
		return 0
	}
	return time.Duration(days) * 24 * time.Hour
}

// GetLicenseStatus returns the current license status using a single point-in-time check.
// It uses a single time.Now() call to avoid inconsistencies at state boundaries.
func GetLicenseStatus(license v3.LicenseKey, gracePeriod time.Duration) LicenseStatus {
	if license.Status.Expiry.IsZero() {
		return LicenseStatusValid
	}
	now := time.Now()
	expiry := license.Status.Expiry.Time
	if now.After(expiry.Add(gracePeriod)) {
		return LicenseStatusExpired
	}
	if now.After(expiry) {
		return LicenseStatusInGracePeriod
	}
	return LicenseStatusValid
}
