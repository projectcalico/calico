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
	gotls "crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/crypto/pkg/tls"
)

// Proxy proxies HTTP based on the provided list of targets
type Proxy struct {
	mux *http.ServeMux
}

// NewProxy returns an initialized Proxy
func NewProxy(tgts []Target) (*Proxy, error) {
	p := &Proxy{
		mux: http.NewServeMux(),
	}

	for i, t := range tgts {
		if t.Dest == nil {
			return nil, fmt.Errorf("bad target %d, no destination", i)
		}
		if len(t.CAFile) != 0 && t.Dest.Scheme != "https" {
			logrus.Debugf("Configuring CA cert for secure communication %s for %s", t.CAFile, t.Dest.Scheme)
			return nil, fmt.Errorf("CA configured for url scheme %q", t.Dest.Scheme)
		}
		hdlr, err := newTargetHandler(t)
		if err != nil {
			return nil, err
		}
		p.mux.HandleFunc(t.Path, hdlr)
		logrus.Debugf("Proxy target %q -> %q", t.Path, t.Dest)
	}

	return p, nil
}

func newTargetHandler(tgt Target) (func(http.ResponseWriter, *http.Request), error) {
	p := httputil.NewSingleHostReverseProxy(tgt.Dest)
	p.FlushInterval = -1

	if tgt.Transport != nil {
		p.Transport = tgt.Transport
	} else if tgt.Dest.Scheme == "https" {
		tlsCfg, err := tls.NewTLSConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS Config: %w", err)
		}

		if tgt.AllowInsecureTLS {
			tlsCfg.InsecureSkipVerify = true
		} else {
			if len(tgt.CAFile) == 0 {
				return nil, fmt.Errorf("failed to create target handler for path %s: ca bundle was empty", tgt.Path)
			}

			logrus.Debugf("Detected secure transport for %s. Will pick up system cert pool", tgt.Dest)
			var ca *x509.CertPool
			ca, err := x509.SystemCertPool()
			if err != nil {
				logrus.WithError(err).Warn("failed to get system cert pool, creating a new one")
				ca = x509.NewCertPool()
			}

			file, err := os.ReadFile(tgt.CAFile)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("could not read cert from file %s", tgt.CAFile))
			}

			ca.AppendCertsFromPEM(file)
			tlsCfg.RootCAs = ca
		}

		// If specified, load and include the provided client certificate for mTLS with the destination.
		if tgt.ClientKeyPath != "" && tgt.ClientCertPath != "" {
			clientCert, err := gotls.LoadX509KeyPair(tgt.ClientCertPath, tgt.ClientKeyPath)
			if err != nil {
				return nil, fmt.Errorf("error load cert key pair for linseed client: %s", err)
			}
			tlsCfg.Certificates = append(tlsCfg.Certificates, clientCert)
			logrus.Info("Using provided client certificates for mTLS")
		}

		p.Transport = &http.Transport{
			TLSClientConfig:   tlsCfg,
			ForceAttemptHTTP2: true,
		}
	}

	return func(w http.ResponseWriter, r *http.Request) {
		logCtx := logrus.WithField("dst", tgt)
		if tgt.PathRegexp != nil {
			if !tgt.PathRegexp.MatchString(r.URL.Path) {
				http.Error(w, "Not found", 404)
				logCtx.Debugf("Received request %s rejected by PathRegexp %q", r.RequestURI, tgt.PathRegexp)
				return
			}
			if tgt.PathReplace != nil {
				logCtx.Debugf("Replacing URL path %s.", r.URL.Path)
				r.URL.Path = tgt.PathRegexp.ReplaceAllString(r.URL.Path, string(tgt.PathReplace))
				logCtx.Debugf("Replaced URL path is now %s.", r.URL.Path)
			}
			if tgt.HostHeader != nil {
				logCtx.Debugf("Rewriting host header to %s", *tgt.HostHeader)
				r.Host = *tgt.HostHeader
			}
		}

		// Get the token value in the handler so if the Token changes we'll pick up the
		// updated token.
		if tgt.Token != nil {
			tok, err := tgt.Token.Token()
			if err != nil {
				http.Error(w, "Internal Server Error, token read failure", 500)
				logCtx.Errorf("Loading token failed %s", err)
			}
			tok.SetAuthHeader(r)
		}

		logCtx.Debugf("Received request %s will proxy to %s", r.RequestURI, tgt.Dest)

		p.ServeHTTP(w, r)
	}, nil
}

// ServeHTTP knows how to proxy HTTP requests to different named targets
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	logrus.Debug("Proxying request")
	p.mux.ServeHTTP(w, r)
	logrus.Debug("Finished proxying request")
}

// GetTargetPath returns the target that would be used.
func (p *Proxy) GetTargetPath(r *http.Request) string {
	_, pat := p.mux.Handler(r)
	return pat
}
