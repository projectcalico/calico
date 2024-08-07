// Copyright (c) 2019-2024 Tigera, Inc. All rights reserved.

package v3

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func addConversionFuncs(scheme *runtime.Scheme) error {
	// Add non-generated conversion functions
	err := scheme.AddFieldLabelConversionFunc(schema.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: "NetworkPolicy"},
		func(label, value string) (string, string, error) {
			switch label {
			case "spec.tier", "metadata.name", "metadata.namespace":
				return label, value, nil
			default:
				return "", "", fmt.Errorf("field label not supported: %s", label)
			}
		},
	)
	if err != nil {
		return err
	}

	err = scheme.AddFieldLabelConversionFunc(schema.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: "GlobalNetworkPolicy"},
		func(label, value string) (string, string, error) {
			switch label {
			case "spec.tier", "metadata.name":
				return label, value, nil
			default:
				return "", "", fmt.Errorf("field label not supported: %s", label)
			}
		},
	)
	if err != nil {
		return err
	}

	err = scheme.AddFieldLabelConversionFunc(schema.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: "GlobalNetworkSet"},
		func(label, value string) (string, string, error) {
			switch label {
			case "metadata.name":
				return label, value, nil
			default:
				return "", "", fmt.Errorf("field label not supported: %s", label)
			}
		},
	)
	if err != nil {
		return err
	}

	err = scheme.AddFieldLabelConversionFunc(schema.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: "NetworkSet"},
		func(label, value string) (string, string, error) {
			switch label {
			case "metadata.name", "metadata.namespace":
				return label, value, nil
			default:
				return "", "", fmt.Errorf("field label not supported: %s", label)
			}
		},
	)
	if err != nil {
		return err
	}

	err = scheme.AddFieldLabelConversionFunc(schema.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: "HostEndpoint"},
		func(label, value string) (string, string, error) {
			switch label {
			case "metadata.name":
				return label, value, nil
			default:
				return "", "", fmt.Errorf("field label not supported: %s", label)
			}
		},
	)
	if err != nil {
		return err
	}

	err = scheme.AddFieldLabelConversionFunc(schema.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: "IPPool"},
		func(label, value string) (string, string, error) {
			switch label {
			case "metadata.name":
				return label, value, nil
			default:
				return "", "", fmt.Errorf("field label not supported: %s", label)
			}
		},
	)
	if err != nil {
		return err
	}

	err = scheme.AddFieldLabelConversionFunc(schema.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: "BGPConfiguration"},
		func(label, value string) (string, string, error) {
			switch label {
			case "metadata.name":
				return label, value, nil
			default:
				return "", "", fmt.Errorf("field label not supported: %s", label)
			}
		},
	)
	if err != nil {
		return err
	}

	err = scheme.AddFieldLabelConversionFunc(schema.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: "BGPPeer"},
		func(label, value string) (string, string, error) {
			switch label {
			case "metadata.name":
				return label, value, nil
			default:
				return "", "", fmt.Errorf("field label not supported: %s", label)
			}
		},
	)
	if err != nil {
		return err
	}

	err = scheme.AddFieldLabelConversionFunc(schema.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: "Profile"},
		func(label, value string) (string, string, error) {
			switch label {
			case "metadata.name":
				return label, value, nil
			default:
				return "", "", fmt.Errorf("field label not supported: %s", label)
			}
		},
	)
	if err != nil {
		return err
	}

	err = scheme.AddFieldLabelConversionFunc(schema.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: "FelixConfiguration"},
		func(label, value string) (string, string, error) {
			switch label {
			case "metadata.name":
				return label, value, nil
			default:
				return "", "", fmt.Errorf("field label not supported: %s", label)
			}
		},
	)
	if err != nil {
		return err
	}

	err = scheme.AddFieldLabelConversionFunc(schema.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: "KubeControllersConfiguration"},
		func(label, value string) (string, string, error) {
			switch label {
			case "metadata.name":
				return label, value, nil
			default:
				return "", "", fmt.Errorf("field label not supported: %s", label)
			}
		},
	)
	if err != nil {
		return err
	}

	err = scheme.AddFieldLabelConversionFunc(schema.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: "ClusterInformation"},
		func(label, value string) (string, string, error) {
			switch label {
			case "metadata.name":
				return label, value, nil
			default:
				return "", "", fmt.Errorf("field label not supported: %s", label)
			}
		},
	)
	if err != nil {
		return err
	}

	err = scheme.AddFieldLabelConversionFunc(schema.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: "Tier"},
		func(label, value string) (string, string, error) {
			switch label {
			case "metadata.name":
				return label, value, nil
			default:
				return "", "", fmt.Errorf("field label not supported: %s", label)
			}
		},
	)
	if err != nil {
		return err
	}

	return nil
}
