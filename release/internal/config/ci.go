package config

import (
	"fmt"
)

type CIConfig struct {
	IsCI   bool   `envconfig:"CI" default:"false"`
	OrgURL string `envconfig:"SEMAPHORE_ORGANIZATION_URL" default:""`
	JobID  string `envconfig:"SEMAPHORE_JOB_ID" default:""`
}

func (c *CIConfig) URL() string {
	if c.IsCI && c.OrgURL != "" {
		return fmt.Sprintf("%s/jobs/%s", c.OrgURL, c.JobID)
	}
	return ""
}
