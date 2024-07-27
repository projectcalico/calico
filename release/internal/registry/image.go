package registry

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
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
	req, err := http.NewRequest(http.MethodHead, manifestURL, nil)
	if err != nil {
		logrus.WithError(err).Error("Failed to create request")
		return false, err
	}
	if registry.URL() == DockerRegistry {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}
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
