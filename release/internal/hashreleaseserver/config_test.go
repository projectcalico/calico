package hashreleaseserver

import (
	"testing"
)

func TestConfigValid(t *testing.T) {
	for _, tc := range []struct {
		name          string
		config        Config
		expectedValid bool
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
			expectedValid: true,
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
			expectedValid: true,
		},
		{
			name: "missing GCS credentials",
			config: Config{
				Host: "localhost",
				User: "user",
				Key:  "/path/to/key",
				Port: "22",
			},
			expectedValid: false,
		},
		{
			name: "missing SSH credentials",
			config: Config{
				CredentialsFile: "/path/to/credentials.json",
				BucketName:      "bucket-name",
			},
			expectedValid: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.config.Valid(); got != tc.expectedValid {
				t.Errorf("Config.Valid() = %v, want %v", got, tc.expectedValid)
			}
		})
	}
}
