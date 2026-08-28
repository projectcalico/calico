package migration

import (
	operatorv1 "github.com/tigera/operator/api/v1"
)

// Converter converts an unmanaged Calico install into an Installation resource which represents
// said install. It will return an error if the unmanaged install cannot be represented by
// an Installation resource.
type Converter interface {
	Convert() (*operatorv1.Installation, error)
}
