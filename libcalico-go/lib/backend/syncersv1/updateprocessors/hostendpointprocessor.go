// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.

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

package updateprocessors

import (
	"errors"
	"fmt"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/watchersyncer"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// Create a new SyncerUpdateProcessor to sync HostEndpoint data in v1 format for
// consumption by both Felix and the BGP daemon.
func NewHostEndpointUpdateProcessor() watchersyncer.SyncerUpdateProcessor {
	return NewConflictResolvingCacheUpdateProcessor(apiv3.KindHostEndpoint, convertHostEndpointV3ToV1)
}

// Convert v3 KVPair to the equivalent v1 KVPair.
func convertHostEndpointV3ToV1(kvp *model.KVPair) (*model.KVPair, error) {
	// Validate against incorrect key/value kinds.  This indicates a code bug rather
	// than a user error.
	v3key, ok := kvp.Key.(model.ResourceKey)
	if !ok || v3key.Kind != apiv3.KindHostEndpoint {
		return nil, errors.New("Key is not a valid HostEndpoint resource key")
	}
	v3res, ok := kvp.Value.(*apiv3.HostEndpoint)
	if !ok {
		return nil, errors.New("Value is not a valid HostEndpoint resource key")
	}

	v1key := model.HostEndpointKey{
		Hostname:   v3res.Spec.Node,
		EndpointID: v3res.GetName(),
	}

	var ipv4Addrs []cnet.IP
	var ipv6Addrs []cnet.IP
	for _, ipString := range v3res.Spec.ExpectedIPs {
		ip := cnet.ParseIP(ipString)
		if ip != nil {
			if ip.Version() == 4 {
				ipv4Addrs = append(ipv4Addrs, *ip)
			} else {
				ipv6Addrs = append(ipv6Addrs, *ip)
			}
		}
	}

	// Convert the EndpointPort type from the API pkg to the v1 model equivalent type
	ports := []model.EndpointPort{}
	for _, port := range v3res.Spec.Ports {
		ports = append(ports, model.EndpointPort{
			Name:     port.Name,
			Protocol: port.Protocol.ToV1(),
			Port:     port.Port,
		})
	}

	qosControls, err := handleQoSControlsAnnotations(v3res.Annotations)
	if err != nil {
		// If QoSControls can't be parsed, log the error but keep processing the host endpoint
		logrus.WithField("hep", v3res.Name).WithError(err).Warn("Error parsing QoSControl annotations")
	}

	v1value := &model.HostEndpoint{
		Name:              v3res.Spec.InterfaceName,
		ExpectedIPv4Addrs: ipv4Addrs,
		ExpectedIPv6Addrs: ipv6Addrs,
		Labels:            uniquelabels.Make(v3res.GetLabels()),
		ProfileIDs:        v3res.Spec.Profiles,
		Ports:             ports,
		QoSControls:       qosControls,
	}

	return &model.KVPair{
		Key:      v1key,
		Value:    v1value,
		Revision: kvp.Revision,
	}, nil
}

func handleQoSControlsAnnotations(annotations map[string]string) (*model.QoSControls, error) {
	var (
		qosControls *model.QoSControls
		errs        []error
	)
	// Calico DSCP value for egress traffic annotation.
	if str, found := annotations[conversion.AnnotationQoSEgressDSCP]; found {
		dscp := numorstring.DSCPFromString(str)
		err := dscp.Validate()
		if err != nil {
			errs = append(errs, fmt.Errorf("error parsing DSCP annotation: %w", err))
		} else {
			qosControls = &model.QoSControls{DSCP: &dscp}
		}
	}

	return qosControls, errors.Join(errs...)
}
