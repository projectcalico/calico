package registry

import (
	"context"
	"fmt"
	"net/http"

	"github.com/docker/distribution/reference"
	"github.com/sirupsen/logrus"
)

// ImageRef represents a container image.
type ImageRef struct {
	ref reference.Named
}

// Repository returns the repository part of the image.
func (i ImageRef) Repository() string {
	return reference.Path(i.ref)
}

// Tag returns the tag part of the image.
func (i ImageRef) Tag() string {
	return reference.TagNameOnly(i.ref).(reference.NamedTagged).Tag()
}

func (i ImageRef) Registry() Registry {
	domain := reference.Domain(i.ref)
	return GetRegistry(domain)
}

func ParseImage(img string) ImageRef {
	ref, err := reference.ParseNormalizedNamed(img)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to parse image")
	}
	return ImageRef{ref}
}

// ImageExists checks if an image exists in a registry.
func ImageExists(image, registryURL string) (bool, error) {
	registry := GetRegistry(registryURL)
	img := Image(image)
	token, err := getBearerToken(registry, fmt.Sprintf("repository:%s:pull", img.Repository()))
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
