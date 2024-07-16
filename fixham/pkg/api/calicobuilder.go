package api

// CalicoBuilder is a component in the Calico project
type CalicoBuilder struct {
	Builder
}

// NewCalicoBuilder returns a new CalicoComponent
func NewCalicoBuilder() *CalicoBuilder {
	return &CalicoBuilder{
		Builder: *NewBuilder(),
	}
}

// Path returns the path used for Calico component
func (c *CalicoBuilder) Path() string {
	return c.Config().RepoRootDir
}
