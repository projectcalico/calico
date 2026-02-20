// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package calc_test

import (
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	kapiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/projectcalico/calico/lib/std/uniquelabels"
	. "github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	calinet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// Istio test data
var (
	// Namespace with istio.io/dataplane-mode=ambient label
	istioNamespaceAmbient = kapiv1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "istio-ambient",
			UID:  types.UID("a0316465-6365-4463-ad63-3564622d3638"),
			Labels: map[string]string{
				apiv3.LabelIstioDataplaneMode: apiv3.LabelIstioDataplaneModeAmbient,
			},
		},
	}

	// Namespace with istio.io/dataplane-mode=none label
	istioNamespaceNone = kapiv1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "istio-none",
			UID:  types.UID("b0316465-6365-4463-ad63-3564622d3638"),
			Labels: map[string]string{
				apiv3.LabelIstioDataplaneMode: apiv3.LabelIstioDataplaneModeNone,
			},
		},
	}

	// Namespace without istio label
	regularNamespace = kapiv1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "regular",
			UID:  types.UID("c0316465-6365-4463-ad63-3564622d3638"),
		},
	}

	// Pod in ambient namespace
	istioWepAmbientKey = WorkloadEndpointKey{
		Hostname:       localHostname,
		OrchestratorID: "orch",
		WorkloadID:     "istio-wep-ambient",
		EndpointID:     "ep1",
	}
	istioWepAmbient = WorkloadEndpoint{
		State: "active",
		Name:  "istio-wep-ambient",
		IPv4Nets: []calinet.IPNet{
			mustParseNet("10.10.1.1/32"),
		},
		IPv6Nets: []calinet.IPNet{
			mustParseNet("fc00:fe10::1/128"),
		},
		Labels: uniquelabels.Make(map[string]string{
			"projectcalico.org/namespace": "istio-ambient",
			"istio.io/dataplane-mode":     "ambient",
		}),
		ProfileIDs: []string{"istio-ambient"},
	}

	// Pod in none namespace
	istioWepNoneKey = WorkloadEndpointKey{
		Hostname:       localHostname,
		OrchestratorID: "orch",
		WorkloadID:     "istio-wep-none",
		EndpointID:     "ep1",
	}
	istioWepNone = WorkloadEndpoint{
		State: "active",
		Name:  "istio-wep-none",
		IPv4Nets: []calinet.IPNet{
			mustParseNet("10.10.3.1/32"),
		},
		IPv6Nets: []calinet.IPNet{
			mustParseNet("fc00:fe10::3/128"),
		},
		Labels: uniquelabels.Make(map[string]string{
			"projectcalico.org/namespace": "istio-none",
		}),
		ProfileIDs: []string{"istio-none"},
	}

	// Pod in regular namespace (no istio labels)
	regularWepKey = WorkloadEndpointKey{
		Hostname:       localHostname,
		OrchestratorID: "orch",
		WorkloadID:     "regular-wep",
		EndpointID:     "ep1",
	}
	regularWep = WorkloadEndpoint{
		State: "active",
		Name:  "regular-wep",
		IPv4Nets: []calinet.IPNet{
			mustParseNet("10.10.4.1/32"),
		},
		IPv6Nets: []calinet.IPNet{
			mustParseNet("fc00:fe10::4/128"),
		},
		Labels: uniquelabels.Make(map[string]string{
			"projectcalico.org/namespace": "regular",
		}),
		ProfileIDs: []string{"regular"},
	}

	// Pod with direct istio.io/dataplane-mode=ambient label
	istioWepDirectAmbientKey = WorkloadEndpointKey{
		Hostname:       localHostname,
		OrchestratorID: "orch",
		WorkloadID:     "istio-wep-direct-ambient",
		EndpointID:     "ep1",
	}
	istioWepDirectAmbient = WorkloadEndpoint{
		State: "active",
		Name:  "istio-wep-direct-ambient",
		IPv4Nets: []calinet.IPNet{
			mustParseNet("10.10.5.1/32"),
		},
		IPv6Nets: []calinet.IPNet{
			mustParseNet("fc00:fe10::5/128"),
		},
		Labels: uniquelabels.Make(map[string]string{
			"projectcalico.org/namespace": "regular",
			apiv3.LabelIstioDataplaneMode: apiv3.LabelIstioDataplaneModeAmbient,
		}),
		ProfileIDs: []string{"regular"},
	}
)
