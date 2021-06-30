// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package calico

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	calico "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
)

func TestInvalidFieldError(t *testing.T) {
	ctx, store, gnpStore := testSetup(t)
	defer testCleanup(t, ctx, store, gnpStore)

	key := "projectcalico.org/globalnetworkpolicies/default/default.foo"
	out := &calico.GlobalNetworkPolicy{}
	obj := &calico.GlobalNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "default.foo"},
		Spec: v3.GlobalNetworkPolicySpec{
			Egress: []v3.Rule{{
				Action: "Allow",
				Destination: v3.EntityRule{
					Selector: "role == 'fish'",
				},
			}},
		},
	}

	err := gnpStore.Create(ctx, key, obj, out, 0)
	if err == nil {
		t.Fatal("Invalid creation succeeded unexpectedly")
	}
	msg := err.Error()
	if strings.Contains(msg, "null") {
		t.Fatalf("Error message includes \"null\": %v", msg)
	}
}
