// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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

package config

import (
	"strings"

	log "github.com/sirupsen/logrus"
)

// LoadConfigFromEnvironment extracts raw config parameters (identified by
// case-insensitive prefix "typha_") from the given OS environment variables.
// An environment entry of "TYPHA_FOO=bar" is translated to "foo": "bar".
func LoadConfigFromEnvironment(environ []string) map[string]string {
	result := make(map[string]string)
	// isSensitiveParam checks whether a config parameter name suggests its value
	// may contain credentials. Matching params have their values redacted in logs.
	// Note: params ending in "file" (e.g. "etcdkeyfile") are file paths, not secrets.
	sensitiveSubstrings := []string{
		"password", "passwd", "passphrase",
		"token", "bearer",
		"secret",
		"credential",
		"authorization",
		"cookie",
		"private",
	}
	sensitiveSuffixes := []string{"key", "cert", "kubeconfig", "kubeconfiginline"}
	isSensitiveParam := func(name string) bool {
		lower := strings.ToLower(name)
		// Params ending in "file" or "path" are file paths, not inline secrets.
		if strings.HasSuffix(lower, "file") || strings.HasSuffix(lower, "path") {
			return false
		}
		for _, sub := range sensitiveSubstrings {
			if strings.Contains(lower, sub) {
				return true
			}
		}
		for _, suffix := range sensitiveSuffixes {
			if strings.HasSuffix(lower, suffix) {
				return true
			}
		}
		return false
	}
	for _, kv := range environ {
		splits := strings.SplitN(kv, "=", 2)
		if len(splits) < 2 {
			log.Warningf("Ignoring malformed environment variable: %#v",
				kv)
			continue
		}
		key := strings.ToLower(splits[0])
		value := splits[1]
		if strings.HasPrefix(key, "typha_") {
			splits = strings.SplitN(key, "_", 2)
			paramName := splits[1]
			// Redact values for env vars that may contain sensitive credentials.
			if isSensitiveParam(paramName) {
				log.Infof("Found typha environment variable: %s=<redacted>",
					paramName)
			} else {
				log.Infof("Found typha environment variable: %s=%q",
					paramName, value)
			}
			result[paramName] = value
		}
	}
	return result
}
