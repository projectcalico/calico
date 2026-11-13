// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package istio

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
	"github.com/projectcalico/calico/operator/pkg/render/istio"
)

// caWarningKey keys the non-Degraded status message for a signer transition in
// progress.
const caWarningKey = "istio-ca"

// trustInputs is what the operator-managed CA and the cluster's current CA
// resolve to for the renderer.
type trustInputs struct {
	localCA    *istio.CA
	source     istio.CASource
	transition *istio.SignerTransition
	ownRoots   []*x509.Certificate
	current    *corev1.Secret
	// requeueAfter is when a transition in progress next has to be looked at.
	requeueAfter time.Duration
	// problems need a human: each sets Degraded and names its source.
	problems []string
	// notice is reported without Degraded: the install works while a signer
	// transition runs, and this says which phase it is in.
	notice string
}

// resolveTrust reads the CA Secrets and validates them. It returns an error
// only for API failures; invalid input is recorded in problems so the rest
// still renders.
func (r *ReconcileIstio) resolveTrust(ctx context.Context) (*trustInputs, error) {
	in := &trustInputs{}

	current, err := r.getSecret(ctx, istio.CACertsSecretName, istio.IstioNamespace)
	if err != nil {
		return nil, err
	}
	in.current = current
	selfSigned, err := r.getSecret(ctx, istio.IstioSelfSignedCASecretName, istio.IstioNamespace)
	if err != nil {
		return nil, err
	}

	if err := r.resolveSigner(ctx, in, selfSigned); err != nil {
		return nil, err
	}
	return in, nil
}

// resolveSigner picks the CA to render from the one istiod signs with and the
// operator-managed CA, moving between them through the signer transition when
// their roots differ. Replacing the root in one step would cut off every
// ztunnel that has not refreshed its certificate yet.
func (r *ReconcileIstio) resolveSigner(ctx context.Context, in *trustInputs, selfSigned *corev1.Secret) error {
	recorded := istio.ReadTransition(in.current)
	current := currentSigner(in.current, selfSigned)
	desired, desiredSource, problem, err := r.resolveDesiredCA(ctx)
	if err != nil {
		return err
	}
	if current.problem != "" {
		in.problems = append(in.problems, current.problem)
	}
	if problem != "" {
		in.problems = append(in.problems, problem)
	}

	if current.problem != "" || desired == nil {
		// cacerts is only ever replaced by a bundle that validated in full, so
		// nothing is rendered. What istiod signs with, and the roots a transition
		// in progress carries, are still what other clusters must trust.
		in.ownRoots = append(append([]*x509.Certificate{}, current.roots...), recorded.Roots()...)
		if recorded.Phase != istio.TransitionNone {
			in.notice = fmt.Sprintf("Istio CA rotation paused at phase %s/4 until the CA is usable", recorded.Phase)
		}
		return nil
	}

	rolled, err := r.istiodRolledOut(ctx, in.current)
	if err != nil {
		return err
	}
	step := istio.StepSignerTransition(istio.TransitionInput{
		Current:       current.ca,
		CurrentSource: current.source,
		Desired:       desired,
		DesiredSource: desiredSource,
		Recorded:      recorded,
		Rolled:        rolled,
		Now:           r.clock(),
		Wait:          istio.SignerTransitionWait(),
	})
	in.localCA, in.source, in.transition = step.Signer, step.Source, step.Transition
	if step.AwaitingRoll {
		in.requeueAfter = utils.StandardRetry
	} else {
		in.requeueAfter = step.RequeueAfter
	}
	if step.Transition != nil {
		in.notice = transitionNotice(step, current.source, desiredSource)
	}
	return nil
}

// signer is the CA istiod signs with now.
type signer struct {
	ca     *istio.CA
	source istio.CASource
	// roots are the roots to publish; they are known even when ca did not validate.
	roots   []*x509.Certificate
	problem string
}

// currentSigner reads the CA istiod signs with: the one in cacerts when it
// exists, since a complete cacerts puts istiod on the plugged-CA path whoever
// made it, else the self-signed CA istiod persisted in istio-ca-secret. An
// install with neither has no signer yet.
func currentSigner(cacerts, selfSigned *corev1.Secret) signer {
	var s signer
	var secret *corev1.Secret
	switch {
	case cacerts != nil:
		secret = cacerts
		s.source = istio.CASource(cacerts.Labels[istio.CACertsLabel])
		if s.source == "" {
			s.source = istio.CASourceUnmanaged
		}
	case selfSigned != nil:
		secret, s.source = selfSigned, istio.CASourceSelfSigned
	default:
		return s
	}

	ca, err := istio.LoadCA(secret.Data)
	if err != nil {
		s.problem = fmt.Sprintf("Secret %s/%s, which istiod signs with, is not a usable CA: %v", secret.Namespace, secret.Name, err)
		// istio-ca-secret holds istiod's own root alone, so what parses there is
		// safe to publish. A bundle may hold other trust anchors, which must not be.
		if s.source == istio.CASourceSelfSigned {
			if roots, err := istio.ParseCACertificates(secret.Data[istio.RootCertKey]); err == nil {
				s.roots = roots
			}
		}
		return s
	}
	s.ca, s.roots = ca, ca.Roots
	return s
}

// resolveDesiredCA is the operator-managed CA, generated the first time.
// Content that does not validate is a problem for a human, not an error.
func (r *ReconcileIstio) resolveDesiredCA(ctx context.Context) (ca *istio.CA, source istio.CASource, problem string, err error) {
	source = istio.CASourceOperatorManaged
	ca, err = r.ensureOperatorCA(ctx, istio.DefaultTrustDomain)
	if _, invalid := err.(invalidCAError); invalid {
		problem = fmt.Sprintf("Secret %s/%s is not a usable CA: %v", common.OperatorNamespace(), istio.OperatorCASecretName, err)
		err = nil
	}
	return ca, source, problem, err
}

// istiodRolledOut reports whether every istiod replica serves the cacerts in
// the cluster.
func (r *ReconcileIstio) istiodRolledOut(ctx context.Context, cacerts *corev1.Secret) (bool, error) {
	if cacerts == nil {
		return false, nil
	}
	d := &appsv1.Deployment{}
	if err := r.Get(ctx, types.NamespacedName{Name: istio.IstioIstiodDeploymentName, Namespace: istio.IstioNamespace}, d); err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return istio.IstiodRolledOut(d, cacerts), nil
}

func (r *ReconcileIstio) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// transitionNotice is the status warning while a transition runs. Until the
// signer switches, it names the CA the mesh moves away from, if the operator
// did not create it.
func transitionNotice(step istio.TransitionStep, currentSource, desiredSource istio.CASource) string {
	t := step.Transition
	from := ""
	if t.Phase < istio.TransitionSwitchSigner && currentSource != desiredSource {
		from = " from " + describeCASource(currentSource)
	}
	return fmt.Sprintf("Istio CA rotation%s, %s", from, t.Phase.Describe(t.Deadline))
}

func describeCASource(source istio.CASource) string {
	switch source {
	case istio.CASourceSelfSigned:
		return fmt.Sprintf("Istio's self-signed CA (%s/%s)", istio.IstioNamespace, istio.IstioSelfSignedCASecretName)
	case istio.CASourceUnmanaged:
		return fmt.Sprintf("a user-provided CA (%s/%s)", istio.IstioNamespace, istio.CACertsSecretName)
	}
	return "the operator-managed CA"
}

// invalidCAError marks Secret content that failed validation, as opposed to an
// API error, so the caller can report it and keep going.
type invalidCAError struct{ error }

func (e invalidCAError) Unwrap() error { return e.error }

// ensureOperatorCA returns the operator-managed CA, generating and persisting it
// the first time. A persisted CA that no longer validates is reported, not
// replaced: a new root would cut off every workload certificate in flight.
func (r *ReconcileIstio) ensureOperatorCA(ctx context.Context, trustDomain string) (*istio.CA, error) {
	key := types.NamespacedName{Name: istio.OperatorCASecretName, Namespace: common.OperatorNamespace()}
	secret := &corev1.Secret{}
	err := r.Get(ctx, key, secret)
	if err != nil && !errors.IsNotFound(err) {
		return nil, err
	}
	if err == nil {
		ca, err := istio.LoadCA(secret.Data)
		if err != nil {
			return nil, invalidCAError{fmt.Errorf("%w (delete the Secret to generate a new CA; this changes the mesh root)", err)}
		}
		return ca, nil
	}

	ca, err := istio.GenerateCA(trustDomain)
	if err != nil {
		return nil, err
	}
	secret = &corev1.Secret{
		TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
		Type:       corev1.SecretTypeOpaque,
		Data:       ca.SecretData(),
	}
	log.Info("Generated the operator-managed Istio CA", "secret", key.String())
	if err := r.Create(ctx, secret); err != nil {
		if !errors.IsAlreadyExists(err) {
			return nil, err
		}
		// Another reconcile won the race; its CA is the one to use.
		return r.ensureOperatorCA(ctx, trustDomain)
	}
	return ca, nil
}

func (r *ReconcileIstio) getSecret(ctx context.Context, name, namespace string) (*corev1.Secret, error) {
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, secret); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return secret, nil
}
