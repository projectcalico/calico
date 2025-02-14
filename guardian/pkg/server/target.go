// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"

	"golang.org/x/oauth2"
	"k8s.io/client-go/transport"
)

type strAsByteSlice []byte

// Target is the format for env variable to set proxy targets
type TargetParam struct {
	// Path is the path portion of the URL based on which we proxy
	Path string `json:"path"`
	// Dest is the destination URL
	Dest string `json:"destination"`
	// TokenPath is where we read the Bearer token from (if non-empty)
	TokenPath string `json:"tokenPath,omitempty"`
	// CABundlePath is where we read the CA bundle from to authenticate the
	// destination (if non-empty)
	CABundlePath string `json:"caBundlePath,omitempty"`
	// PathRegexp, if not nil, checks if Regexp matches the path
	PathRegexp strAsByteSlice `json:"pathRegexp,omitempty"`
	// PathReplace if not nil will be used to replace PathRegexp matches
	PathReplace strAsByteSlice `json:"pathReplace,omitempty"`

	// HostHeader rewrites the host value for the proxied request.
	HostHeader *string `json:"hostHeader,omitempty"`
	// AllowInsecureTLS allows https with insecure tls settings
	AllowInsecureTLS bool `json:"allowInsecureTLS,omitempty"`

	// ClientCertPath and ClientKeyPath can be set for mTLS on the connection
	// from Voltron to the destination.
	ClientCertPath string `json:"clientCertPath"`
	ClientKeyPath  string `json:"clientKeyPath"`

	Unauthenticated bool `json:"unauthenticated,omitempty"`
}

// Target describes which path is proxied to what destination URL
type Target struct {
	Path  string
	Dest  *url.URL
	Token oauth2.TokenSource
	CAPem string

	// PathRegexp, if not nil, check if Regexp matches the path
	PathRegexp *regexp.Regexp
	// PathReplace if not nil will be used to replace PathRegexp matches
	PathReplace []byte

	// HostHeader if not nil will replace the Host header for the proxied request.
	HostHeader *string

	// Transport to use for this target. If nil, Proxy will provide one
	Transport        http.RoundTripper
	AllowInsecureTLS bool

	// Configures client key and certificate for mTLS from Voltron with the target.
	ClientKeyPath  string
	ClientCertPath string
}

func ParseTargets(tgts []TargetParam) ([]Target, error) {
	var ret []Target

	// pathSet helps keep track of the paths we've seen so we don't have duplicates
	pathSet := make(map[string]bool)

	for _, t := range tgts {
		if t.Path == "" {
			return nil, errors.New("proxy target path cannot be empty")
		} else if pathSet[t.Path] {
			return nil, fmt.Errorf("duplicate proxy target path %s", t.Path)
		}

		pt := Target{
			Path:             t.Path,
			AllowInsecureTLS: t.AllowInsecureTLS,
		}

		if t.ClientKeyPath != "" && t.ClientCertPath != "" {
			pt.ClientKeyPath = t.ClientKeyPath
			pt.ClientCertPath = t.ClientCertPath
		} else if t.ClientKeyPath != "" || t.ClientCertPath != "" {
			return nil, fmt.Errorf("must specify both ClientKeyPath and ClientCertPath")
		}

		var err error
		pt.Dest, err = url.Parse(t.Dest)
		if err != nil {
			return nil, fmt.Errorf("incorrect URL %q for path %q: %s", t.Dest, t.Path, err)
		}

		if pt.Dest.Scheme == "https" && !t.AllowInsecureTLS && t.CABundlePath == "" {
			return nil, fmt.Errorf("target for path '%s' must specify the ca bundle if AllowInsecureTLS is false when the scheme is https", t.Path)
		}

		if t.TokenPath != "" {
			// Read the token from file to verify the token exists
			_, err := os.ReadFile(t.TokenPath)
			if err != nil {
				return nil, fmt.Errorf("failed reading token from %s: %s", t.TokenPath, err)
			}

			pt.Token = transport.NewCachedFileTokenSource(t.TokenPath)
		}

		if t.CABundlePath != "" {
			pt.CAPem = t.CABundlePath
		}

		if t.PathReplace != nil && t.PathRegexp == nil {
			return nil, fmt.Errorf("PathReplace specified but PathRegexp is not")
		}

		if t.PathRegexp != nil {
			r, err := regexp.Compile(string(t.PathRegexp))
			if err != nil {
				return nil, fmt.Errorf("PathRegexp failed: %s", err)
			}
			pt.PathRegexp = r
		}
		pt.PathReplace = t.PathReplace
		pt.HostHeader = t.HostHeader

		pathSet[pt.Path] = true
		ret = append(ret, pt)
	}

	return ret, nil
}
