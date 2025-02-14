package tunnel

import (
	"errors"
	"net/url"
	"time"
)

// Option is a common format for New() options
type Option func(*tunnel) error

type DialerOption func(*sessionDialer) error

// WithKeepAliveSettings sets the Keep Alive settings for the tunnel.
func WithDialerKeepAliveSettings(enable bool, intervalDuration time.Duration) DialerOption {
	return func(dialer *sessionDialer) error {
		dialer.keepAliveEnable = enable
		dialer.keepAliveInterval = intervalDuration
		return nil
	}
}

func WithDialerTimeout(dialTimeout time.Duration) DialerOption {
	return func(dialer *sessionDialer) error {
		dialer.timeout = dialTimeout
		return nil
	}
}

func WithDialerRetryAttempts(retryAttempts int) DialerOption {
	return func(dialer *sessionDialer) error {
		dialer.retryAttempts = retryAttempts
		return nil
	}
}

func WithDialerRetryInterval(retryInterval time.Duration) DialerOption {
	return func(dialer *sessionDialer) error {
		dialer.retryInterval = retryInterval
		return nil
	}
}

func WithDialerHTTPProxyURL(httpProxyURL *url.URL) DialerOption {
	return func(dialer *sessionDialer) error {
		if dialer.tlsConfig == nil {
			return errors.New("WithHTTPProxyURL: TLS dialer is required to use HTTP proxy")
		}
		dialer.httpProxyURL = httpProxyURL
		return nil
	}
}
