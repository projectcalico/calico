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

package logstorage

const (
	// Secret and volume name used for client certificate and key. Used by Linseed and es-gateway
	// when mTLS to external Elasticsearch is enabled. The secret contains the client certificate
	// and key to present to elastic.
	ExternalCertsSecret     = "tigera-secure-external-es-certs"
	ExternalCertsVolumeName = "tigera-secure-external-es-certs"

	// ExternalESPublicCertName and ExternalKBPublicCertName are the names of the public certificates
	// used as part of CA bundles to trust external Elasticsearch and Kibana instances.
	ExternalESPublicCertName = "tigera-secure-es-http-certs-public"
	ExternalKBPublicCertName = "tigera-secure-kb-http-certs-public"
)
