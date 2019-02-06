package model

type DeletionMarker interface {
	MarkDeleted()
	IsDeleted() bool
}
