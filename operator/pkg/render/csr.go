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

package render

import (
	"context"

	certificatesv1 "k8s.io/api/certificates/v1"
)

// TLSAsset is one certificate the CSR controller will sign for, keyed elsewhere by
// the secret name the requesting pod mounts.
type TLSAsset struct {
	ServiceAccountName      string
	ServiceAccountNamespace string
	ValidDNSNames           []string

	// Authorize replaces the service account match, for assets that more than one
	// service account may request.
	Authorize CSRAuthorizer
}

// CSRAuthorizer reports whether the requestor of a CSR may ask for the asset.
type CSRAuthorizer func(context.Context, *certificatesv1.CertificateSigningRequest) (bool, error)

// CSRSubject is the workload a certificate is issued to, matched against the request.
type CSRSubject struct {
	// Name is the second half of the CSR name.
	Name string

	// IP is the only address the certificate may carry, empty when there is none.
	IP string
}

// CSRSubjectResolver identifies the subject of a request no pod issued, returning
// nil for one the variant does not recognize.
type CSRSubjectResolver func(context.Context, *certificatesv1.CertificateSigningRequest) (*CSRSubject, error)

// CSRData is what a variant contributes to the CSR controller. It lives here so the
// controller need not import extensions.
type CSRData struct {
	// AllowedAssets are the certificates the variant will sign for, added to the
	// signable set the controller matches requests against.
	AllowedAssets map[string]TLSAsset

	// RequiresSigningRole reports whether a variant component will submit a signing
	// request, which the controller needs the CSR ClusterRole for.
	RequiresSigningRole bool

	// ResolveSubject identifies the subject of requests that no pod issued.
	ResolveSubject CSRSubjectResolver
}

// CSRDataFromInputs returns the CSRData an extension stashed in the inputs. The zero
// value means the variant signs for nothing.
func CSRDataFromInputs(ri Inputs) CSRData {
	return ExtractExtensionData[CSRData](ri)
}
