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
				CredentialsFile: "/path/to/credentials.json",
				BucketName:      "bucket-name",
			},
			expectedValid: true,
		},
		{
			name: "missing GCS credentials",
			config: Config{
				BucketName: "bucket-name",
			},
			expectedValid: false,
		},
		{
			name: "missing bucket name",
			config: Config{
				CredentialsFile: "/path/to/credentials.json",
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
