package tunnel

import (
	"errors"
	"net/url"
	"time"
)

// Option is a common format for New() options
type Option func(*tunnel) error

// WithKeepAliveSettings sets the Keep Alive settings for the tunnel.
func WithKeepAliveSettings(enable bool, intervalDuration time.Duration) Option {
	return func(t *tunnel) error {
		t.keepAliveEnable = enable
		t.keepAliveInterval = intervalDuration
		return nil
	}
}

func WithDialTimeout(dialTimeout time.Duration) Option {
	return func(t *tunnel) error {
		t.dialer.setTimeout(dialTimeout)
		return nil
	}
}

func WithDialRetryAttempts(retryAttempts int) Option {
	return func(t *tunnel) error {
		t.dialer.setRetryAttempts(retryAttempts)
		return nil
	}
}

func WithDialRetryInterval(retryInterval time.Duration) Option {
	return func(t *tunnel) error {
		t.dialer.setRetryInterval(retryInterval)
		return nil
	}
}

func WithHTTPProxyURL(httpProxyURL *url.URL) Option {
	return func(t *tunnel) error {
		if t.dialer.getTLSConfig() == nil {
			return errors.New("WithHTTPProxyURL: TLS dialer is required to use HTTP proxy")
		}
		t.dialer.setHTTPProxyURL(httpProxyURL)
		return nil
	}
}
