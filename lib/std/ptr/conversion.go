package ptr

// ToPtr returns a pointer to the given value.
func ToPtr[V any](v V) *V {
	return &v
}
