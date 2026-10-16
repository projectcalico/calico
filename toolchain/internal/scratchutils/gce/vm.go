// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package gce creates and deletes a GCE VM via the compute API and drives it over
// SSH (ssh.go) — no gcloud, so callers can run from a distroless image. Create
// does not wait for the VM to be usable; DialSSH's retry is the readiness check.
package gce

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"
)

// Config describes the VM to create. Zones are tried in order (capacity), and the
// first that succeeds is returned. The project is the Client's, not a field here.
type Config struct {
	Name          string
	Zones         []string
	MachineType   string // e.g. "n2-standard-16"
	DiskType      string // e.g. "pd-ssd"
	DiskSizeGB    int64
	Image         string // exact image name; wins over ImageFamily when set
	ImageFamily   string // e.g. "ubuntu-2404-lts-amd64"
	ImageProject  string // e.g. "ubuntu-os-cloud"
	MaxRun        time.Duration
	Labels        map[string]string
	StartupScript string // bash run as the GCE startup-script (on the VM)
}

// Client is a compute API client scoped to one project.
type Client struct {
	svc     *compute.Service
	project string
}

// New builds a client using Application Default Credentials. Point
// GOOGLE_APPLICATION_CREDENTIALS at the service-account key (a mounted secret)
// before calling -- the cmd wrappers do this from COMPUTE_SA_KEY.
func New(ctx context.Context, project string) (*Client, error) {
	svc, err := compute.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("compute client: %w", err)
	}
	return &Client{svc: svc, project: project}, nil
}

// PerZoneTimeout bounds ONE zone's attempt, so a degraded zone can be skipped
// rather than consuming the whole budget. Three minutes because the failure mode
// is slowness, not rejection: a zone can accept an insert and take tens of minutes
// to finish it.
const PerZoneTimeout = 3 * time.Minute

// Create inserts the instance in the first zone that accepts it and returns that
// zone. The VM gets an external IP, cloud-platform scope, and a max-run-duration
// GCP reclaims it at -- eventually, since that reclaim is itself an operation and
// can queue behind a wedged insert. Every zone's error is reported, not just the
// last.
func (c *Client) Create(ctx context.Context, cfg Config) (zone string, err error) {
	if len(cfg.Zones) == 0 {
		return "", fmt.Errorf("no zones configured")
	}
	var errs []error
	for _, z := range cfg.Zones {
		if err := ctx.Err(); err != nil {
			errs = append(errs, fmt.Errorf("%s: not attempted: %w", z, err))
			continue
		}
		fmt.Fprintf(os.Stderr, "[gce] trying %s in %s\n", cfg.Name, z)
		if err := c.createInZone(ctx, z, cfg); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", z, err))
			continue
		}
		return z, nil
	}
	return "", fmt.Errorf("could not create %s in any zone: %w", cfg.Name, errors.Join(errs...))
}

// createInZone attempts one zone under its own deadline.
func (c *Client) createInZone(ctx context.Context, zone string, cfg Config) error {
	zctx, cancel := context.WithTimeout(ctx, PerZoneTimeout)
	defer cancel()

	op, err := c.svc.Instances.Insert(c.project, zone, c.instanceSpec(zone, cfg)).Context(zctx).Do()
	if err != nil {
		return fmt.Errorf("insert: %w", err)
	}
	if err := c.waitZoneOp(zctx, zone, op.Name); err != nil {
		// The insert was accepted, so an instance may exist. Left behind it would run
		// to max-run-duration while we boot another elsewhere -- two VMs for one job.
		c.deleteBestEffort(zone, cfg.Name)
		return fmt.Errorf("wait for insert: %w", err)
	}
	return nil
}

// deleteBestEffort builds its own context: the caller's is typically already
// expired, which is why we are here.
func (c *Client) deleteBestEffort(zone, name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	fmt.Fprintf(os.Stderr, "[gce] cleaning up abandoned %s in %s\n", name, zone)
	if err := c.Delete(ctx, zone, name); err != nil {
		fmt.Fprintf(os.Stderr, "[gce] cleanup of %s in %s failed: %v (max-run-duration is the backstop)\n", name, zone, err)
	}
}

func (c *Client) instanceSpec(zone string, cfg Config) *compute.Instance {
	inst := &compute.Instance{
		Name:        cfg.Name,
		MachineType: fmt.Sprintf("zones/%s/machineTypes/%s", zone, cfg.MachineType),
		Labels:      cfg.Labels,
		Disks: []*compute.AttachedDisk{{
			Boot:       true,
			AutoDelete: true,
			InitializeParams: &compute.AttachedDiskInitializeParams{
				SourceImage: sourceImage(cfg),
				DiskSizeGb:  cfg.DiskSizeGB,
				DiskType:    fmt.Sprintf("zones/%s/diskTypes/%s", zone, cfg.DiskType),
			},
		}},
		// One NAT access config = an ephemeral external IP (SSH from the run step).
		NetworkInterfaces: []*compute.NetworkInterface{{
			AccessConfigs: []*compute.AccessConfig{{Type: "ONE_TO_ONE_NAT", Name: "External NAT"}},
		}},
		ServiceAccounts: []*compute.ServiceAccount{{
			Email:  "default",
			Scopes: []string{compute.CloudPlatformScope},
		}},
	}
	// Optional: the ci-base image is already provisioned, so createvm passes none.
	// Only set it for a stock image.
	if cfg.StartupScript != "" {
		inst.Metadata = &compute.Metadata{Items: []*compute.MetadataItems{
			{Key: "startup-script", Value: new(cfg.StartupScript)},
		}}
	}
	if cfg.MaxRun > 0 {
		inst.Scheduling = &compute.Scheduling{
			ProvisioningModel:         "STANDARD",
			InstanceTerminationAction: "DELETE",
			MaxRunDuration:            &compute.Duration{Seconds: int64(cfg.MaxRun.Seconds())},
		}
	}
	return inst
}

// Delete removes the instance and waits for the delete operation to finish. A
// not-found instance is treated as already deleted.
func (c *Client) Delete(ctx context.Context, zone, name string) error {
	op, err := c.svc.Instances.Delete(c.project, zone, name).Context(ctx).Do()
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return fmt.Errorf("delete %s in %s: %w", name, zone, err)
	}
	return c.waitZoneOp(ctx, zone, op.Name)
}

// FindZone returns the zone of an instance with this name in any state, or "" if
// there is none. For cleanup: deletevm wants a TERMINATED VM too, since it is
// stopped but still holding its disk.
func (c *Client) FindZone(ctx context.Context, name string) (string, error) {
	found, err := c.listInstances(ctx, name)
	if err != nil {
		return "", err
	}
	return pickZone(name, found, false)
}

// FindLiveZone returns the zone of a USABLE instance with this name. An instance
// that is stopping, stopped or suspended is an error rather than a target -- for
// a caller about to SSH in and run a job, that VM is not a place to run it, and
// picking it would fail confusingly or, worse, half-work.
func (c *Client) FindLiveZone(ctx context.Context, name string) (string, error) {
	found, err := c.listInstances(ctx, name)
	if err != nil {
		return "", err
	}
	return pickZone(name, found, true)
}

// listInstances finds every instance of this name, across all zones.
func (c *Client) listInstances(ctx context.Context, name string) ([]zoneInstance, error) {
	// The value must be quoted -- an unquoted name with a - or . is a syntax error,
	// not a non-match -- and AggregatedList pages even for a single match.
	call := c.svc.Instances.AggregatedList(c.project).Filter(fmt.Sprintf("name=%q", name))
	var found []zoneInstance
	for {
		agg, err := call.Context(ctx).Do()
		if err != nil {
			return nil, err
		}
		for scope, list := range agg.Items {
			// scope is "zones/<zone>".
			z := strings.TrimPrefix(scope, "zones/")
			for _, inst := range list.Instances {
				found = append(found, zoneInstance{zone: z, status: inst.Status})
			}
		}
		if agg.NextPageToken == "" {
			break
		}
		call = call.PageToken(agg.NextPageToken)
	}
	return found, nil
}

// zoneInstance is one instance of a given name, and where and how it is.
type zoneInstance struct {
	zone   string
	status string
}

// goingAway reports a status from which the instance will not become usable -- it
// is shutting down, already stopped, or tearing down. Every remaining value of
// Instance.Status (PENDING, PROVISIONING, STAGING, RUNNING, REPAIRING) either is
// usable or may still become so.
func goingAway(status string) bool {
	switch status {
	case "STOPPING", "STOPPED", "SUSPENDING", "SUSPENDED", "TERMINATED",
		"DEPROVISIONING", "PENDING_STOP":
		return true
	}
	return false
}

// pickZone chooses which instance of this name to act on. Names are only
// zone-unique and Create can leave one behind, so two is possible; two LIVE ones
// are refused rather than resolved by map order.
//
// requireLive is the caller's intent: a run step errors on a dying VM rather than
// running a job on it, cleanup reaps either.
func pickZone(name string, found []zoneInstance, requireLive bool) (string, error) {
	var live, dying []zoneInstance
	for _, zi := range found {
		if goingAway(zi.status) {
			dying = append(dying, zi)
		} else {
			live = append(live, zi)
		}
	}
	switch {
	case len(live) > 1:
		return "", fmt.Errorf("%s exists in more than one zone (%s); set ZONE to pick one", name, describe(live))
	case len(live) == 1:
		return live[0].zone, nil
	case len(dying) == 0:
		return "", nil // no instance of that name at all
	case requireLive:
		return "", fmt.Errorf("%s exists but is not usable (%s)", name, describe(dying))
	case len(dying) > 1:
		return "", fmt.Errorf("%s exists in more than one zone (%s); set ZONE to pick one", name, describe(dying))
	default:
		return dying[0].zone, nil
	}
}

func describe(set []zoneInstance) string {
	out := make([]string, 0, len(set))
	for _, zi := range set {
		out = append(out, zi.zone+"="+zi.status)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// waitZoneOp blocks until a zone operation reaches DONE, surfacing its error.
func (c *Client) waitZoneOp(ctx context.Context, zone, op string) error {
	for {
		var got *compute.Operation
		if err := retry(ctx, "wait op "+op, func() (err error) {
			got, err = c.svc.ZoneOperations.Wait(c.project, zone, op).Context(ctx).Do()
			return err
		}); err != nil {
			return err
		}
		if got.Status == "DONE" {
			if got.Error != nil && len(got.Error.Errors) > 0 {
				return fmt.Errorf("%s: %s", got.Error.Errors[0].Code, got.Error.Errors[0].Message)
			}
			return nil
		}
	}
}

// sourceImage resolves the boot image: an exact name when Image is set, else the
// family, which always yields its newest member. The pin lets a job hold one image
// steady while newer releases land in the family.
func sourceImage(cfg Config) string {
	if cfg.Image != "" {
		return fmt.Sprintf("projects/%s/global/images/%s", cfg.ImageProject, cfg.Image)
	}
	return fmt.Sprintf("projects/%s/global/images/family/%s", cfg.ImageProject, cfg.ImageFamily)
}

// isNotFound reports a 404 from the compute API. Matching the status beats
// matching the message: the prose varies by endpoint and could change under us.
func isNotFound(err error) bool {
	var gerr *googleapi.Error
	return errors.As(err, &gerr) && gerr.Code == http.StatusNotFound
}
