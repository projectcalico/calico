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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/avast/retry-go/v4"
	"github.com/docker/docker/api/types/registry"
	"github.com/sirupsen/logrus"
)

var defaultDockerConfigDir = filepath.Join(os.Getenv("HOME"), ".config/docker")

type DockerConfig struct {
	Auths map[string]registry.AuthConfig `json:"auths"`
}

func dockerConfigDir() string {
	configDir := os.Getenv("DOCKER_CONFIG")
	if configDir == "" {
		configDir = defaultDockerConfigDir
	}
	return configDir
}

// readDockerConfig reads the docker config file.
func readDockerConfig() (DockerConfig, error) {
	dockerConfigPath := filepath.Join(dockerConfigDir(), "config.json")
	file, err := os.Open(dockerConfigPath)
	if err != nil {
		logrus.WithError(err).Error("failed to open docker config file")
		return DockerConfig{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		logrus.WithError(err).Error("failed to read docker config file")
		return DockerConfig{}, err
	}
	var dockerConfig DockerConfig
	if err := json.Unmarshal(data, &dockerConfig); err != nil {
		logrus.WithError(err).Error("failed to unmarshal docker config")
		return DockerConfig{}, err
	}
	return dockerConfig, nil
}

// getAuthFromDockerConfig retrieves the auth from the docker config.
func getAuthFromDockerConfig(registryURL string) (registry.AuthConfig, error) {
	dockerConfig, err := readDockerConfig()
	if err != nil {
		return registry.AuthConfig{}, err
	}
	for reg, auth := range dockerConfig.Auths {
		if strings.Contains(reg, registryURL) {
			decoded, err := base64.URLEncoding.DecodeString(auth.Auth)
			if err != nil {
				return registry.AuthConfig{}, fmt.Errorf("failed to decode auth: %w", err)
			}
			parts := strings.Split(string(decoded), ":")
			return registry.AuthConfig{
				Username:      parts[0],
				Password:      parts[1],
				ServerAddress: registryURL,
			}, nil
		}
	}
	return registry.AuthConfig{}, fmt.Errorf("no auth found for %s", registryURL)
}

// getBearerToken retrieves a bearer token to use for the image.
func getBearerToken(registry Registry, scope string) (string, error) {
	return getBearerTokenWithAuth("", registry, scope)
}

// getBearerTokenWithDefaultAuth retrieves a bearer token to use for the image with default authentication.
// Default authentication is the authentication from the docker config.
func getBearerTokenWithDefaultAuth(registry Registry, scope string) (string, error) {
	auth, err := getAuthFromDockerConfig(registry.URL())
	if err != nil {
		return "", fmt.Errorf("failed to get auth from docker config: %w", err)
	}
	// We use retry.DoWithData to re-attempt getting bearer tokens.
	// We set attempts to 5, the delay between attempts to 1000ms, and we set a custom
	// retry function. In this case, we only retry if we got a "too many requests" error
	// from the server, but we could add in connection timeouts, etc.
	token, err := retry.DoWithData(func() (string, error) {
		return getBearerTokenWithAuth(fmt.Sprintf("%s:%s", auth.Username, auth.Password), registry, scope)
	}, retry.Attempts(5), retry.Delay(1000), retry.RetryIf(func(err error) bool {
		return err.Error() == "too many requests"
	}))
	return token, err
}

// getBearerTokenWithAuth retrieves a bearer token to use for the image with given authentication.
func getBearerTokenWithAuth(auth string, registry Registry, scope string) (string, error) {
	tokenURL := registry.TokenURL(scope)
	logrus.WithField("tokenURL", tokenURL).Debug("Getting bearer token")
	req, err := http.NewRequest(http.MethodGet, tokenURL, nil)
	if err != nil {
		return "", err
	}
	if auth != "" {
		parts := strings.Split(auth, ":")
		req.SetBasicAuth(parts[0], parts[1])
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	// If we got HTTP 200, decode the response and return the token
	if res.StatusCode == http.StatusOK {
		resp := map[string]interface{}{}
		if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
			return "", err
		}
		return resp["token"].(string), nil
	}

	// If we got HTTP 429, log that we got throttled and then return the error
	if res.StatusCode == http.StatusTooManyRequests {
		logrus.WithFields(logrus.Fields{
			"TokenURL": tokenURL,
			"Scope":    scope,
		}).Error("server is throttling our requests, backing off")
		return "", fmt.Errorf("too many requests")
	}
	return "", fmt.Errorf("failed to get bearer token: %s", res.Status)
}
