package builder

type Option func(*ReleaseBuilder) error

func WithRepoRoot(root string) Option {
	return func(r *ReleaseBuilder) error {
		r.repoRoot = root
		return nil
	}
}

func IsHashRelease() Option {
	return func(r *ReleaseBuilder) error {
		r.isHashRelease = true
		return nil
	}
}
