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
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/docker/docker/api/types/registry"
	"github.com/sirupsen/logrus"
)

var defaultDockerConfigDir = filepath.Join(os.Getenv("HOME"), ".config/docker")
var dockerConfigOnce = sync.OnceValues(readDockerConfig)

// DockerConfig stores configuration data from a user's config.json
type DockerConfig struct {
	Auths       map[string]registry.AuthConfig `json:"auths"`
	CredHelpers map[string]string              `json:"credHelpers"`
	CredsStore  string                         `json:"credsStore"`
}

type credentialHelperData struct {
	Username      string `json:"Username"`
	Password      string `json:"Secret"`
	ServerAddress string `json:"ServerURL"`
}

func (cd credentialHelperData) toAuthConfig() registry.AuthConfig {
	return registry.AuthConfig{
		Username:      cd.Username,
		Password:      cd.Password,
		ServerAddress: cd.ServerAddress,
	}
}

func dockerConfigDir() string {
	configDir := os.Getenv("DOCKER_CONFIG")
	if configDir == "" {
		configDir = defaultDockerConfigDir
	}
	return configDir
}

// GetAuth gets authentication information for a given registry, caching it if necessary
func (dc *DockerConfig) GetAuth(registryURL string) (registry.AuthConfig, error) {
	logWithRegistry := logrus.WithField("registryURL", registryURL)
	// If we have an auth config already, we can use that
	if authConfig, ok := dc.Auths[registryURL]; ok {
		logWithRegistry.Debug("Got cached authentication config from docker config")
		return authConfig, nil
	}

	// If we don't have an auth config, let's see if we have a credentials config
	if credsConfig, ok := dc.CredHelpers[registryURL]; ok {
		dockerCreds, err := getCredsFromCredentialHelper(credsConfig, registryURL)
		if err != nil {
			logWithRegistry.Debug("Failed to get credentials from registry credential helper")
		} else {
			logWithRegistry.Debug("Got authentication information from registry credential helper")
			dc.Auths[registryURL] = dockerCreds.toAuthConfig()
			return dc.Auths[registryURL], nil
		}
	}
	// We don't have a configured auth or a credsHelper. Let's at least try
	// the secret store.
	if dc.CredsStore != "" {
		dockerCreds, err := getCredsFromCredentialHelper(dc.CredsStore, registryURL)
		if err != nil {
			logWithRegistry.Debug("Failed to get credentials from default credsStore")
		} else {
			logWithRegistry.Debug("Got authentication information from default credsStore")
			dc.Auths[registryURL] = dockerCreds.toAuthConfig()
			return dc.Auths[registryURL], nil
		}
	}
	return registry.AuthConfig{}, fmt.Errorf("Unable to find any credentials for this registry")
}

// readDockerConfig reads the docker config file.
func readDockerConfig() (DockerConfig, error) {
	dockerConfigPath := filepath.Join(dockerConfigDir(), "config.json")
	logrus.WithField("configfile", dockerConfigPath).Debug("Reading docker config file")
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

	for reg, auth := range dockerConfig.Auths {
		logWithReg := logrus.WithField("registry", reg)
		// If auth.Auth is not a string, it's base64 encoded credentials
		if auth.Auth != "" {
			decoded, err := base64.URLEncoding.DecodeString(auth.Auth)
			if err != nil {
				return DockerConfig{}, fmt.Errorf("failed to decode auth field for config %s: %w", reg, err)
			}
			parts := strings.Split(string(decoded), ":")
			if len(parts) != 2 {
				return DockerConfig{}, fmt.Errorf("decoded invalid auth for config %s: %w", reg, err)
			}
			dockerConfig.Auths[reg] = registry.AuthConfig{
				Username:      parts[0],
				Password:      parts[1],
				Auth:          auth.Auth,
				ServerAddress: reg,
			}
		} else {
			// If the config has a defined CredHelper for this registry, try to use it
			if helper, ok := dockerConfig.CredHelpers[reg]; ok {
				logWithHelper := logWithReg.WithField("helper", helper)
				logWithHelper.Debug("Getting credentials from credential helper")
				credsData, err := getCredsFromCredentialHelper(helper, reg)
				if err != nil {
					logWithHelper.WithError(err).Error("Unable to get credentials from defined helper")
				} else {
					dockerConfig.Auths[reg] = credsData.toAuthConfig()
				}
				continue
			}
			// If we couldn't get credentials from the CredHelper, or if it wasn't defined,
			// try the user's default credentials store
			if dockerConfig.CredsStore != "" {
				logWithCredsStore := logWithReg.WithField("credsStore", dockerConfig.CredsStore)
				logWithCredsStore.Debug("getting credentials from default credential store")
				credsData, err := getCredsFromCredentialHelper(dockerConfig.CredsStore, reg)
				if err != nil {
					logWithCredsStore.WithError(err).Error("Unable to get credentials from credential store")
				} else {
					dockerConfig.Auths[reg] = credsData.toAuthConfig()
				}
			}
		}
	}
	return dockerConfig, nil
}

func getCredsFromCredentialHelper(helperName string, domainName string) (credentialHelperData, error) {
	credentialHelperName := fmt.Sprintf("docker-credential-%s", helperName)
	credHelperLog := logrus.WithFields(logrus.Fields{
		"CredsHelper": credentialHelperName,
		"Registry":    domainName,
	})
	credHelperLog.Debug("Getting credential data")
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.Command(credentialHelperName, "get")

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return credentialHelperData{}, fmt.Errorf("unable to execute credential helper: %w", err)
	}
	defer stdin.Close()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return credentialHelperData{}, fmt.Errorf("unable to execute credential helper: %v", err)
	}
	defer stdout.Close()

	outputBuffer := fmt.Sprintf("%s\n", domainName)

	if err = cmd.Start(); err != nil {
		return credentialHelperData{}, fmt.Errorf("failed to execute credential helper %s: %w", credentialHelperName, err)
	}

	_, err = io.WriteString(stdin, outputBuffer)
	if err != nil {
		return credentialHelperData{}, fmt.Errorf("failed to send data to credential helper %s: %w", credentialHelperName, err)
	}

	err = stdin.Close()
	if err != nil {
		return credentialHelperData{}, fmt.Errorf("failed to close subprocess stdin: %w", err)
	}

	buf, err := io.ReadAll(stdout)
	if err != nil {
		return credentialHelperData{}, err
	}
	err = cmd.Wait()
	if err != nil {
		// If we got an error and ExitCode is 1, then the credential helper didn't
		// find anything (which isn't necessarily an error)
		if cmd.ProcessState.ExitCode() == 1 {
			return credentialHelperData{}, nil
		}
		return credentialHelperData{}, err
	}

	credsData := credentialHelperData{}
	if err := json.Unmarshal(buf, &credsData); err != nil {

		credHelperLog.Error("Couldn't unmarshal JSON data")
		return credentialHelperData{}, err
	}
	return credsData, nil
}

// getAuthFromDockerConfig retrieves the auth from the docker config.
func getAuthFromDockerConfig(registryURL string) (registry.AuthConfig, error) {
	dockerConfig, err := dockerConfigOnce()
	if err != nil {
		return registry.AuthConfig{}, fmt.Errorf("unable to fetch docker config: %w", err)
	}

	authConfig, err := dockerConfig.GetAuth(registryURL)
	if err != nil {
		return registry.AuthConfig{}, err
	}

	return authConfig, nil
}

// getBearerToken retrieves a bearer token to use for the image. If we have
// authentication information, use it; otherwise, try without.
func getBearerToken(registry Registry, scope string) (string, error) {
	// Try to authenticate by default
	bearerToken, err := getBearerTokenWithDefaultAuth(registry, scope)
	if err == nil {
		return bearerToken, err
	}
	// We didn't have authentication information. Try without authenticating.
	bearerToken, err = getBearerTokenWithAuth("", registry, scope)
	if err != nil {
		return "", fmt.Errorf("failed to authenticate to registry and failed to get a bearer token without")
	}
	return bearerToken, nil
}

// getBearerTokenWithDefaultAuth retrieves a bearer token to use for the image with default authentication.
// Default authentication is the authentication from the docker config.
func getBearerTokenWithDefaultAuth(registry Registry, scope string) (string, error) {
	auth, err := getAuthFromDockerConfig(registry.URL())
	if err != nil {
		return "", fmt.Errorf("failed to get auth from docker config: %w", err)
	}
	return getBearerTokenWithAuth(fmt.Sprintf("%s:%s", auth.Username, auth.Password), registry, scope)
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
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get bearer token: %s", res.Status)
	}
	resp := map[string]interface{}{}
	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		return "", err
	}
	return resp["token"].(string), nil
}
