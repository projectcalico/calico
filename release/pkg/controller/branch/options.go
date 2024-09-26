package branch

type Option func(*BranchController) error

func WithRepoRemote(remote string) Option {
	return func(b *BranchController) error {
		b.remote = remote
		return nil
	}
}

func WithRepoRoot(root string) Option {
	return func(b *BranchController) error {
		b.repoRoot = root
		return nil
	}
}

func WithMainBranch(branch string) Option {
	return func(b *BranchController) error {
		b.mainBranch = branch
		return nil
	}
}

func WithDevTagIdentifier(devTag string) Option {
	return func(b *BranchController) error {
		b.devTagIdentifier = devTag
		return nil
	}
}

func WithReleaseBranchPrefix(prefix string) Option {
	return func(b *BranchController) error {
		b.releaseBranchPrefix = prefix
		return nil
	}
}

func WithValidate(validate bool) Option {
	return func(b *BranchController) error {
		b.validate = validate
		return nil
	}
}

func WithPublish(publish bool) Option {
	return func(b *BranchController) error {
		b.publish = publish
		return nil
	}
}
