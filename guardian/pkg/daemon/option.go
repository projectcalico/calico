package daemon

import "github.com/projectcalico/calico/guardian/pkg/server"

type Option func(opts *configOpts) error

func WithExtraProxyTargets(targets ...server.Target) Option {
	return func(opts *configOpts) error {
		opts.proxyTargets = append(opts.proxyTargets, targets...)
		return nil
	}
}
