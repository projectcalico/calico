package registry

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/docker/distribution/reference"
	"github.com/sirupsen/logrus"
)

// ImageMap maps the image name to the repository.
var ImageMap = map[string]string{
	"typha":                     "calico/typha",
	"calicoctl":                 "calico/ctl",
	"flannel":                   "coreos/flannel",
	"flexvol":                   "calico/pod2daemon-flexvol",
	"key-cert-provisioner":      "calico/key-cert-provisioner",
	"csi-node-driver-registrar": "calico/node-driver-registrar",
}

// privateImages is a list of images that require authentication.
var privateImages = []string{"calico/api", "calico/cni-windows", "calico/node-windows"}

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

func (i ImageRef) IsPrivate() bool {
	for _, img := range privateImages {
		if i.Repository() == img {
			return true
		}
	}
	return false
}

func ParseImage(img string) ImageRef {
	ref, err := reference.ParseNormalizedNamed(img)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to parse image")
	}
	return ImageRef{ref}
}

// ImageExists checks if an image exists in a registry.
func ImageExists(img ImageRef) (bool, error) {
	registry := img.Registry()
	scope := fmt.Sprintf("repository:%s:pull", img.Repository())
	var token string
	var err error
	if img.IsPrivate() {
		token, err = getBearerTokenWithDefaultAuth(registry, scope)
	} else {
		token, err = getBearerToken(registry, scope)
	}
	if err != nil {
		return false, err
	}
	manifestURL := registry.ManifestURL(img)
	logrus.WithFields(logrus.Fields{
		"image":       img,
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
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("unable to find image: %s", body)
	}
	return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
}
