package api

type Package interface {
	Path() string
	PackageName() string
}
