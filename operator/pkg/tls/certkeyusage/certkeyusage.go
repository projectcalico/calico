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

package certkeyusage

import "crypto/x509"

var secretKeyUsage = map[string][]x509.ExtKeyUsage{}

func SetCertKeyUsage(secretName string, usage []x509.ExtKeyUsage) {
	secretKeyUsage[secretName] = usage
}

// GetKeyUsage looks up the expected usage for keys by name. Currently these are certs that in a
// legacy install may have been created with only Server ext key usage but now with linseed they
// they need to also have client for mTLS.
// This is a varaible so that we can override this for testing purposes.
func GetCertKeyUsage(secret string) []x509.ExtKeyUsage {
	if usage, ok := secretKeyUsage[secret]; ok {
		return usage
	}
	return []x509.ExtKeyUsage{}
}
