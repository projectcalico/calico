// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package clientv2

import (
	"context"
	"net"

	apiv2 "github.com/projectcalico/libcalico-go/lib/apis/v2"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/watch"
	log "github.com/sirupsen/logrus"
)

// IPPoolInterface has methods to work with IPPool resources.
type IPPoolInterface interface {
	Create(ctx context.Context, res *apiv2.IPPool, opts options.SetOptions) (*apiv2.IPPool, error)
	Update(ctx context.Context, res *apiv2.IPPool, opts options.SetOptions) (*apiv2.IPPool, error)
	Delete(ctx context.Context, name string, opts options.DeleteOptions) (*apiv2.IPPool, error)
	Get(ctx context.Context, name string, opts options.GetOptions) (*apiv2.IPPool, error)
	List(ctx context.Context, opts options.ListOptions) (*apiv2.IPPoolList, error)
	Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error)
}

// ipPools implements IPPoolInterface
type ipPools struct {
	client client
}

// Create takes the representation of a IPPool and creates it.  Returns the stored
// representation of the IPPool, and an error, if there is any.
func (r ipPools) Create(ctx context.Context, res *apiv2.IPPool, opts options.SetOptions) (*apiv2.IPPool, error) {
	// Validate the IPPool before creating the resource.
	if err := r.validateAndSetDefaults(res); err != nil {
		return nil, err
	}

	// Enable IPIP globally if required.  Do this before the Create so if it fails the user
	// can retry the same command.
	err := r.maybeEnableIPIP(ctx, res)
	if err != nil {
		return nil, err
	}

	out, err := r.client.resources.Create(ctx, opts, apiv2.KindIPPool, res)
	if out != nil {
		return out.(*apiv2.IPPool), err
	}
	return nil, err

}

// Update takes the representation of a IPPool and updates it. Returns the stored
// representation of the IPPool, and an error, if there is any.
func (r ipPools) Update(ctx context.Context, res *apiv2.IPPool, opts options.SetOptions) (*apiv2.IPPool, error) {
	// Validate the IPPool updating the resource.
	if err := r.validateAndSetDefaults(res); err != nil {
		return nil, err
	}

	// Enable IPIP globally if required.  Do this before the Update so if it fails the user
	// can retry the same command.
	err := r.maybeEnableIPIP(ctx, res)
	if err != nil {
		return nil, err
	}

	out, err := r.client.resources.Update(ctx, opts, apiv2.KindIPPool, res)
	if out != nil {
		return out.(*apiv2.IPPool), err
	}
	return nil, err
}

// Delete takes name of the IPPool and deletes it. Returns an error if one occurs.
func (r ipPools) Delete(ctx context.Context, name string, opts options.DeleteOptions) (*apiv2.IPPool, error) {
	out, err := r.client.resources.Delete(ctx, opts, apiv2.KindIPPool, noNamespace, name)
	if out != nil {
		return out.(*apiv2.IPPool), err
	}
	return nil, err
}

// Get takes name of the IPPool, and returns the corresponding IPPool object,
// and an error if there is any.
func (r ipPools) Get(ctx context.Context, name string, opts options.GetOptions) (*apiv2.IPPool, error) {
	out, err := r.client.resources.Get(ctx, opts, apiv2.KindIPPool, noNamespace, name)
	if out != nil {
		return out.(*apiv2.IPPool), err
	}
	return nil, err
}

// List returns the list of IPPool objects that match the supplied options.
func (r ipPools) List(ctx context.Context, opts options.ListOptions) (*apiv2.IPPoolList, error) {
	res := &apiv2.IPPoolList{}
	if err := r.client.resources.List(ctx, opts, apiv2.KindIPPool, apiv2.KindIPPoolList, res); err != nil {
		return nil, err
	}
	return res, nil
}

// Watch returns a watch.Interface that watches the IPPools that match the
// supplied options.
func (r ipPools) Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error) {
	return r.client.resources.Watch(ctx, opts, apiv2.KindIPPool)
}

// validateAndSetDefaults validates IPPool fields.
func (_ ipPools) validateAndSetDefaults(pool *apiv2.IPPool) error {
	errFields := []cerrors.ErroredField{}

	// Spec.CIDR field must not be empty.
	if pool.Spec.CIDR == "" {
		return cerrors.ErrorValidation{
			ErroredFields: []cerrors.ErroredField{{
				Name:   "IPPool.Spec.CIDR",
				Reason: "IPPool CIDR must be specified",
			}},
		}
	}

	// Make sure the CIDR is parsable.
	ipAddr, cidr, err := cnet.ParseCIDR(pool.Spec.CIDR)
	if err != nil {
		return cerrors.ErrorValidation{
			ErroredFields: []cerrors.ErroredField{{
				Name:   "IPPool.Spec.CIDR",
				Reason: "IPPool CIDR must be a valid subnet",
			}},
		}
	}

	// Make sure IPIPMode is defaulted to "Never".
	if len(pool.Spec.IPIPMode) == 0 {
		pool.Spec.IPIPMode = apiv2.IPIPModeNever
	}

	// IPIP cannot be enabled for IPv6.
	if cidr.Version() == 6 && pool.Spec.IPIPMode != apiv2.IPIPModeNever {
		errFields = append(errFields, cerrors.ErroredField{
			Name:   "IPPool.Spec.IPIP.Mode",
			Reason: "IPIP is not supported on an IPv6 IP pool",
		})
	}

	// The Calico IPAM places restrictions on the minimum IP pool size.  If
	// the ippool is enabled, check that the pool is at least the minimum size.
	if !pool.Spec.Disabled {
		ones, bits := cidr.Mask.Size()
		log.Debugf("Pool CIDR: %s, num bits: %d", cidr.String(), bits-ones)
		if bits-ones < 6 {
			if cidr.Version() == 4 {
				errFields = append(errFields, cerrors.ErroredField{
					Name:   "IPPool.Spec.CIDR",
					Reason: "IPv4 pool size is too small (min /26) for use with Calico IPAM",
				})
			} else {
				errFields = append(errFields, cerrors.ErroredField{
					Name:   "IPPool.Spec.CIDR",
					Reason: "IPv6 pool size is too small (min /122) for use with Calico IPAM",
				})
			}
		}
	}

	// The Calico CIDR should be strictly masked
	log.Debugf("IPPool CIDR: %s, Masked IP: %d", pool.Spec.CIDR, cidr.IP)
	if cidr.IP.String() != ipAddr.String() {
		errFields = append(errFields, cerrors.ErroredField{
			Name:   "IPPool.Spec.CIDR",
			Reason: "IP pool CIDR is not strictly masked",
		})
	}

	// IPv4 link local subnet.
	ipv4LinkLocalNet := net.IPNet{
		IP:   net.ParseIP("169.254.0.0"),
		Mask: net.CIDRMask(16, 32),
	}
	// IPv6 link local subnet.
	ipv6LinkLocalNet := net.IPNet{
		IP:   net.ParseIP("fe80::"),
		Mask: net.CIDRMask(10, 128),
	}

	// IP Pool CIDR cannot overlap with IPv4 or IPv6 link local address range.
	if cidr.Version() == 4 && cidr.IsNetOverlap(ipv4LinkLocalNet) {
		errFields = append(errFields, cerrors.ErroredField{
			Name:   "IPPool.Spec.CIDR",
			Reason: "IP pool range overlaps with IPv4 Link Local range 169.254.0.0/16",
		})
	}

	if cidr.Version() == 6 && cidr.IsNetOverlap(ipv6LinkLocalNet) {
		errFields = append(errFields, cerrors.ErroredField{
			Name:   "IPPool.Spec.CIDR",
			Reason: "IP pool range overlaps with IPv6 Link Local range fe80::/10",
		})
	}

	// Return the errors if we have one or more validation errors.
	if len(errFields) > 0 {
		return cerrors.ErrorValidation{
			ErroredFields: errFields,
		}
	}

	return nil
}

// maybeEnableIPIP enables global IPIP if a default setting is not already configured
// and the pool has IPIP enabled.
func (c ipPools) maybeEnableIPIP(ctx context.Context, pool *apiv2.IPPool) error {
	if pool.Spec.IPIPMode == apiv2.IPIPModeNever {
		log.Debug("IPIP is not enabled for this pool - no need to check global setting")
		return nil
	}

	var err error
	ipEnabled := true
	for i := 0; i < maxApplyRetries; i++ {
		log.WithField("Retry", i).Debug("Checking global IPIP setting")
		res, err := c.client.FelixConfigurations().Get(ctx, "default", options.GetOptions{})
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok && err != nil {
			log.WithError(err).Debug("Error getting current FelixConfiguration resource")
			return err
		}

		if res == nil {
			log.Debug("Global FelixConfiguration does not exist - creating")
			res = apiv2.NewFelixConfiguration()
			res.Name = "default"
		} else if res.Spec.IpInIpEnabled != nil {
			// A value for the default config is set so leave unchanged.  It may be set to false,
			// so log the actual value - but we shouldn't update it if someone has explicitly
			// disabled it globally.
			log.WithField("IpInIpEnabled", res.Spec.IpInIpEnabled).Debug("Global IpInIpEnabled setting is already configured")
			return nil
		}

		// Enable IpInIp and do the Create or Update.
		res.Spec.IpInIpEnabled = &ipEnabled
		if res.ResourceVersion == "" {
			res, err = c.client.FelixConfigurations().Create(ctx, res, options.SetOptions{})
			if _, ok := err.(cerrors.ErrorResourceAlreadyExists); ok {
				log.Debug("FelixConfiguration already exists - retry update")
				continue
			}
		} else {
			res, err = c.client.FelixConfigurations().Update(ctx, res, options.SetOptions{})
			if _, ok := err.(cerrors.ErrorResourceUpdateConflict); ok {
				log.Debug("FelixConfiguration update conflict - retry update")
				continue
			}
		}

		if err == nil {
			log.Debug("FelixConfiguration updated successfully")
			return nil
		}

		log.WithError(err).Debug("Error updating FelixConfiguration to enable IPIP")
		return err
	}

	// Return the error from the final Update.
	log.WithError(err).Info("Too many conflict failures attempting to update FelixConfiguration to enable IPIP")
	return err
}
