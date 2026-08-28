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

package extensions

import (
	"errors"
	"fmt"

	operatorv1 "github.com/tigera/operator/api/v1"
)

// degraded carries the status reason a controller reports for an error the
// extension returned.
type degraded struct {
	error
	reason operatorv1.TigeraStatusReason
}

func (e degraded) Unwrap() error {
	return e.error
}

// Degradedf returns an error the controller degrades with under the given reason.
func Degradedf(reason operatorv1.TigeraStatusReason, format string, args ...any) error {
	return degraded{error: fmt.Errorf(format, args...), reason: reason}
}

// InvalidConfigf reports configuration the variant does not support.
func InvalidConfigf(format string, args ...any) error {
	return Degradedf(operatorv1.ResourceValidationError, format, args...)
}

// NotReadyf reports a dependency the extension is waiting on. Controllers wait for
// a watch rather than failing.
func NotReadyf(format string, args ...any) error {
	return Degradedf(operatorv1.ResourceNotReady, format, args...)
}

// DegradedReason returns the reason an extension attached to err, if it attached one.
func DegradedReason(err error) (operatorv1.TigeraStatusReason, bool) {
	var d degraded
	if errors.As(err, &d) {
		return d.reason, true
	}
	return "", false
}
