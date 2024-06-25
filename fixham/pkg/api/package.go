package api

type Package interface {
	// Path returns the path of the package
	Path() string
	// PackageName returns the package name
	PackageName() string
}
