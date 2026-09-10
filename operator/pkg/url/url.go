// Copyright (c) 2021-2024 Tigera, Inc. All rights reserved.

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

package url

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ParseEndpoint parses an endpoint of the form scheme://host:port and returns the components.
func ParseEndpoint(endpoint string) (string, string, string, error) {
	url, err := url.Parse(endpoint)
	if err != nil {
		return "", "", "", err
	}
	splits := strings.Split(url.Host, ":")
	if len(splits) != 2 {
		return "", "", "", fmt.Errorf("invalid host: %s", url.Host)
	}
	return url.Scheme, splits[0], splits[1], nil
}

func ParseHostPortFromHTTPProxyString(proxyURL string) (string, error) {
	parsedProxyURL, err := url.ParseRequestURI(proxyURL)
	if err != nil {
		return "", err
	}

	return ParseHostPortFromHTTPProxyURL(parsedProxyURL)
}

func ParseHostPortFromHTTPProxyURL(url *url.URL) (string, error) {
	parsedScheme := url.Scheme
	if parsedScheme == "" || (parsedScheme != "http" && parsedScheme != "https") {
		return "", fmt.Errorf("unexpected scheme for HTTP proxy URL: %s", parsedScheme)
	}

	if url.Port() != "" {
		// Host is already in host:port form.
		return url.Host, nil
	}

	// Scheme is either http or https at this point.
	if url.Scheme == "http" {
		return net.JoinHostPort(url.Host, "80"), nil
	} else {
		return net.JoinHostPort(url.Host, "443"), nil
	}
}
