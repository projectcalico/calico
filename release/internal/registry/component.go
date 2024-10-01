package registry

import "fmt"

// Component represents a component in the pinned version file.
type Component struct {
	Version  string `yaml:"version"`
	Image    string `yaml:"image,omitempty"`
	Registry string `yaml:"registry,omitempty"`
}

// ImageRef returns the image reference of the component.
func (c Component) ImageRef() ImageRef {
	return ParseImage(c.String())
}

// String returns the string representation of the component.
// The string representation is in the format of registry/image:version.
func (c Component) String() string {
	if c.Registry == "" {
		return fmt.Sprintf("%s:%s", c.Image, c.Version)
	}
	return fmt.Sprintf("%s/%s:%s", c.Registry, c.Image, c.Version)
}

type OperatorComponent struct {
	Component
}

func (c OperatorComponent) InitImage() Component {
	return Component{
		Version:  c.Version,
		Image:    fmt.Sprintf("%s-init", c.Image),
		Registry: c.Registry,
	}
}
