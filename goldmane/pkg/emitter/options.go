package emitter

import "sigs.k8s.io/controller-runtime/pkg/client"

type Option func(*Emitter)

func WithURL(url string) Option {
	return func(e *Emitter) {
		e.url = url
	}
}

func WithCACertPath(path string) Option {
	return func(e *Emitter) {
		e.caCert = path
	}
}

func WithClientKeyPath(path string) Option {
	return func(e *Emitter) {
		e.clientKey = path
	}
}

func WithClientCertPath(path string) Option {
	return func(e *Emitter) {
		e.clientCert = path
	}
}

func WithKubeClient(kcli client.Client) Option {
	return func(e *Emitter) {
		e.kcli = kcli
	}
}

func WithServerName(name string) Option {
	return func(e *Emitter) {
		e.serverName = name
	}
}
