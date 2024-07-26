package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
)

const (
	QuayRegistry   = "quay.io"
	DockerRegistry = "docker.io"
)

// Image represents a container image.
type Image string

// Repository returns the repository part of the image.
func (d Image) Repository() string {
	parts := strings.Split(string(d), ":")
	return parts[0]
}

// Tag returns the tag part of the image.
func (d Image) Tag() string {
	parts := strings.Split(string(d), ":")
	if len(parts) > 1 {
		return parts[1]
	}
	return "latest"
}

// Registry represents a container registry.
type Registry interface {
	URL() string
	TokenURL(repository string) string
	ManifestURL(img Image) string
}

// GetRegistry returns a Registry based on the registry string.
func GetRegistry(registry string) Registry {
	switch registry {
	case QuayRegistry:
		return &Quay{}
	case DockerRegistry:
		return &Docker{}
	default:
		return &Docker{}
	}
}

// getBearerToken retrieves a bearer token to use for the image.
func getBearerToken(registry Registry, img Image) (string, error) {
	tokenURL := registry.TokenURL(img.Repository())
	req, err := http.NewRequest(http.MethodGet, tokenURL, nil)
	if err != nil {
		return "", err
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

// ImageExists checks if an image exists in a registry.
func ImageExists(image, registryURL string) (bool, error) {
	registry := GetRegistry(registryURL)
	img := Image(image)
	token, err := getBearerToken(registry, img)
	if err != nil {
		return false, err
	}
	manifestURL := registry.ManifestURL(img)
	logrus.WithFields(logrus.Fields{
		"image":       image,
		"manifestURL": manifestURL,
	}).Debug("Checking if image exists")
	req, err := http.NewRequest(http.MethodGet, manifestURL, nil)
	if err != nil {
		logrus.WithError(err).Error("Failed to create request")
		return false, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	resp, err := http.DefaultClient.Do(req.WithContext(context.Background()))
	if err != nil {
		logrus.WithError(err).Error("Failed to get manifest")
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return true, nil
	} else if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
}
