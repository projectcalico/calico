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
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"

	"github.com/sirupsen/logrus"
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

type TargetOption func(*Target) error

func WithAllowInsecureTLS() TargetOption {
	return func(t *Target) error {
		t.AllowInsecureTLS = true
		return nil
	}
}

func WithToken(path string) TargetOption {
	return func(t *Target) error {
		_, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed reading token from %s: %w", path, err)
		}

		t.Token = transport.NewCachedFileTokenSource(path)
		return nil
	}
}

func WithCAPem(path string) TargetOption {
	return func(t *Target) error {
		t.CAPem = path
		return nil
	}
}

func WithPathReplace(path string, reg string) TargetOption {
	return func(t *Target) error {
		t.PathReplace = []byte(path)
		r, err := regexp.Compile(reg)
		if err != nil {
			return fmt.Errorf("PathRegexp failed: %s", err)
		}
		t.PathRegexp = r
		return nil
	}
}

func WithHostHeader(hostHeader string) TargetOption {
	return func(t *Target) error {
		t.HostHeader = &hostHeader
		return nil
	}
}

func WithCertKeyPair(certPath, keyPath string) TargetOption {
	return func(t *Target) error {
		t.ClientCertPath = certPath
		t.ClientKeyPath = keyPath
		return nil
	}
}

func MustCreateTarget(path, dest string, opts ...TargetOption) Target {
	if path == "" {
		logrus.Fatal("proxy target path cannot be empty")
	}

	destURL, err := url.Parse(dest)
	if err != nil {
		logrus.WithError(err).Fatalf("incorrect URL %s for path %s", dest, path)
	}

	target := &Target{
		Path: path,
		Dest: destURL,
	}

	for _, opt := range opts {
		if err := opt(target); err != nil {
			logrus.WithError(err).Fatalf("failed to apply option")
		}
	}

	if target.Dest.Scheme == "https" && !target.AllowInsecureTLS && target.CAPem == "" {
		logrus.Fatalf("target for path '%s' must specify the ca bundle if AllowInsecureTLS is false when the scheme is https", path)
	}

	if target.PathReplace != nil && target.PathRegexp == nil {
		logrus.Fatalf("PathReplace specified but PathRegexp is not")
	}

	return *target
}
