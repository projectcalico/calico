package registry

import (
	"encoding/json"
	"fmt"
	"net/http"
)

const (
	QuayRegistry   = "quay.io"
	DockerRegistry = "docker.io"
)

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
