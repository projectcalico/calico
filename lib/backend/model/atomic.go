package model

type AtomicDelete interface {
	SetDelete()
	GetDelete() bool
}
