package registry

const (
	QuayRegistry   = "quay.io"
	DockerRegistry = "docker.io"
)

// Registry represents a container registry.
type Registry interface {
	URL() string
	TokenURL(scope string) string
	ManifestURL(img ImageRef) string
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
