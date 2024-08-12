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

func WithPreReleaseValidation(validate bool) Option {
	return func(r *ReleaseBuilder) error {
		r.validate = validate
		return nil
	}
}

func WithVersions(calicoVersion, operatorVersion string) Option {
	return func(r *ReleaseBuilder) error {
		r.calicoVersion = calicoVersion
		r.operatorVersion = operatorVersion
		return nil
	}
}
