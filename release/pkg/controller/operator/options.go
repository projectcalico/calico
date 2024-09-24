package operator

type Option func(*OperatorController) error

func WithRepoRoot(root string) Option {
	return func(o *OperatorController) error {
		o.repoRoot = root
		return nil
	}
}

func WithRepoRemote(remote string) Option {
	return func(o *OperatorController) error {
		o.remote = remote
		return nil
	}
}

func WithRepoOrganization(org string) Option {
	return func(o *OperatorController) error {
		o.repoOrg = org
		return nil
	}
}

func WithRepoName(name string) Option {
	return func(o *OperatorController) error {
		o.repoName = name
		return nil
	}
}

func WithMainBranch(branch string) Option {
	return func(o *OperatorController) error {
		o.mainBranch = branch
		return nil
	}
}

func WithDevTagIdentifier(devTag string) Option {
	return func(o *OperatorController) error {
		o.devTagIdentifier = devTag
		return nil
	}
}

func WithReleaseBranchPrefix(prefix string) Option {
	return func(o *OperatorController) error {
		o.releaseBranchPrefix = prefix
		return nil
	}
}

func WithValidate(validate bool) Option {
	return func(o *OperatorController) error {
		o.validate = validate
		return nil
	}
}

func WithPublish(publish bool) Option {
	return func(o *OperatorController) error {
		o.publish = publish
		return nil
	}
}
