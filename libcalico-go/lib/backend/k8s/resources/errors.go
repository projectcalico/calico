// Copyright (c) 2016,2020 Tigera, Inc. All rights reserved.

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
	"strings"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/errors"
)

// K8sErrorToCalico returns the equivalent libcalico error for the given
// kubernetes error.
func K8sErrorToCalico(ke error, id interface{}) error {
	if ke == nil {
		return nil
	}

	if kerrors.IsAlreadyExists(ke) {
		return errors.ErrorResourceAlreadyExists{
			Err:        ke,
			Identifier: id,
		}
	}
	if kerrors.IsNotFound(ke) {
		return errors.ErrorResourceDoesNotExist{
			Err:        ke,
			Identifier: id,
		}
	}
	if kerrors.IsForbidden(ke) || kerrors.IsUnauthorized(ke) {
		return errors.ErrorConnectionUnauthorized{
			Err: ke,
		}
	}
	if kerrors.IsConflict(ke) {
		// Treat precondition errors as not found.
		if strings.Contains(ke.Error(), "UID in precondition") {
			return errors.ErrorResourceDoesNotExist{
				Err:        ke,
				Identifier: id,
			}
		}
		return errors.ErrorResourceUpdateConflict{
			Err:        ke,
			Identifier: id,
		}
	}
	if kerrors.IsResourceExpired(ke) {
		// Re-use the Kubernetes resource expired type.
		return ke
	}
	if keStat, ok := ke.(kerrors.APIStatus); ok {
		// Look for the errors we get when we try to patch a resource but it has been recreated or revved.
		if details := keStat.Status().Details; details != nil {
			uidInvalid := false
			revInvalid := false
			somethingElse := false
			for _, c := range details.Causes {
				if c.Field == "metadata.uid" && c.Type == metav1.CauseTypeFieldValueInvalid {
					uidInvalid = true
					continue
				}
				if c.Field == "metadata.resourceVersion" && c.Type == metav1.CauseTypeFieldValueInvalid {
					revInvalid = true
					continue
				}
				somethingElse = true
			}
			if uidInvalid && !somethingElse {
				// The UID in the patch was incorrect; this means that the resource we tried to update
				// has been deleted and recreated with a new UID.
				return errors.ErrorResourceDoesNotExist{
					Err:        ke,
					Identifier: id,
				}
			}
			if revInvalid && !somethingElse {
				// The revision in the patch was incorrect but the UID was OK; this means someone else modified
				// the resource under our feet.
				return errors.ErrorResourceUpdateConflict{
					Err:        ke,
					Identifier: id,
				}
			}
		}
	}
	return errors.ErrorDatastoreError{
		Err:        ke,
		Identifier: id,
	}
}
