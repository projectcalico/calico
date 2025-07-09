package server

import (
	"context"

	"k8s.io/apiserver/pkg/authorization/authorizer"
)

const kubeControllerManagerUser = "system:kube-controller-manager"

func NewAllowUser(alwaysAllowUsers []string) authorizer.Authorizer {

	return authorizer.AuthorizerFunc(func(ctx context.Context, a authorizer.Attributes) (authorized authorizer.Decision, reason string, err error) {
		if a.GetUser() == nil {
			return authorizer.DecisionNoOpinion, "no user info", nil
		}
		user := a.GetUser().GetName()
		for _, u := range alwaysAllowUsers {
			if u == user {
				return authorizer.DecisionAllow, "user is allowed", nil
			}
		}
		return authorizer.DecisionNoOpinion, "", nil
	})
}
