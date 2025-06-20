package hashreleaseserver

import (
	"testing"
)

func TestConfigValid(t *testing.T) {
	for _, tc := range []struct {
		name     string
		config   Config
		expected bool
	}{
		{
			name: "all fields set",
			config: Config{
				Host:            "localhost",
				User:            "user",
				Key:             "/path/to/key",
				Port:            "22",
				KnownHosts:      "/path/to/known_hosts",
				CredentialsFile: "/path/to/credentials.json",
				BucketName:      "bucket-name",
			},
			expected: true,
		},
		{
			name: "known hosts not set",
			config: Config{
				Host:            "localhost",
				User:            "user",
				Key:             "/path/to/key",
				Port:            "22",
				CredentialsFile: "/path/to/credentials.json",
				BucketName:      "bucket-name",
			},
			expected: true,
		},
		{
			name: "missing GCS credentials",
			config: Config{
				Host: "localhost",
				User: "user",
				Key:  "/path/to/key",
				Port: "22",
			},
			expected: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.config.Valid(); got != tc.expected {
				t.Errorf("Config.Valid() = %v, want %v", got, tc.expected)
			}
		})
	}
}
