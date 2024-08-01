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

	"github.com/docker/docker/api/types/registry"
	"github.com/sirupsen/logrus"
)

// getBearerToken retrieves a bearer token to use for the image.
func getBearerToken(registry Registry, scope string) (string, error) {
	return getAuthenticatedBearerToken("", registry, scope)
}

// getAuthenticatedBearerToken retrieves a bearer token to use for the image with authentication.
func getAuthenticatedBearerToken(auth string, registry Registry, scope string) (string, error) {
	tokenURL := registry.TokenURL(scope)
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

// getRegistryAuthConfig retrieves the registry auth config.
func getRegistryAuthConfig(accessAuth, registryURL string) (registry.AuthConfig, error) {
	if accessAuth != "" {
		parts := strings.Split(accessAuth, ":")
		return registry.AuthConfig{
			Username:      parts[0],
			Password:      parts[1],
			ServerAddress: registryURL,
		}, nil
	}
	dockerConfigPath := filepath.Join(os.Getenv("HOME"), ".docker", "config.json")
	file, err := os.Open(dockerConfigPath)
	if err != nil {
		logrus.WithError(err).Error("failed to open docker config file")
		return registry.AuthConfig{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		logrus.WithError(err).Error("failed to read docker config file")
		return registry.AuthConfig{}, err
	}
	var dockerConfig map[string]interface{}
	if err := json.Unmarshal(data, &dockerConfig); err != nil {
		logrus.WithError(err).Error("failed to unmarshal docker config")
		return registry.AuthConfig{}, err
	}
	auths := dockerConfig["auths"].(map[string]interface{})
	for reg, auth := range auths {
		if strings.Contains(reg, registryURL) {
			authConfig := auth.(map[string]interface{})
			return registry.AuthConfig{
				Auth:          authConfig["auth"].(string),
				ServerAddress: reg,
			}, nil
		}
	}
	return registry.AuthConfig{}, fmt.Errorf("no auth found for %s", registryURL)
}

// registryAuthStr returns the base64 encoded registry auth string.
func registryAuthStr(accessAuth string, registry Registry) (string, error) {
	registryAuthConfig, err := getRegistryAuthConfig(accessAuth, registry.URL())
	if err != nil {
		logrus.WithError(err).Error("failed to get auth config")
		return "", err
	}
	registryAuth, err := json.Marshal(registryAuthConfig)
	if err != nil {
		logrus.WithError(err).Error("failed to marshal auth config")
		return "", err
	}
	return base64.URLEncoding.EncodeToString(registryAuth), nil
}
