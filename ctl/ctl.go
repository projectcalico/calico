package ctl

import (
	ctlClient "github.com/projectcalico/ctl/client"
)

type Client = ctlClient.Client

// NewClient returns a new instance of the ctl client.
func NewClient(packageName string) *Client {
	return &Client{
		PackageName: packageName,
	}
}
