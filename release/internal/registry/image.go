// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package registry

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

const TigeraOperatorImage = "tigera/operator"

func CheckImage(image string) (bool, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return false, fmt.Errorf("failed to parse image reference for %s: %w", image, err)
	}

	_, err = remote.Head(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		// HTTP 404 is the canonical "manifest not present at this tag" response;
		// treat it as a clean "image not published" verdict rather than a probe failure.
		var terr *transport.Error
		if errors.As(err, &terr) && terr.StatusCode == http.StatusNotFound {
			return false, nil
		}
		return false, fmt.Errorf("failed to get image descriptor for %s: %w", image, err)
	}
	return true, nil
}
