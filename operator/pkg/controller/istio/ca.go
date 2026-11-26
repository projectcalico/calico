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

package istio

import (
	"context"
	"crypto/x509"
	"fmt"
	"maps"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
	"github.com/projectcalico/calico/operator/pkg/render/istio"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
)

// caWarningKey keys the non-Degraded status message for a signer transition in
// progress.
const caWarningKey = "istio-ca"

// trustInputs is what the Istio CR, the Secrets it names and the cluster's
// current CA resolve to for the renderer.
type trustInputs struct {
	localCA    *istio.CA
	source     istio.CASource
	transition *istio.SignerTransition
	additional []*x509.Certificate
	ownRoots   []*x509.Certificate
	current    *corev1.Secret
	// requeueAfter is when a transition in progress next has to be looked at.
	requeueAfter time.Duration
	// problems need a human: each sets Degraded and names its source.
	problems []string
	// notice is reported without Degraded: the install works while a signer
	// transition runs, and this says which phase it is in.
	notice string
	// userCACerts is set when istiod signs with a cacerts the operator did not
	// create.
	userCACerts bool
}

// resolveTrust reads the CA and trust anchor Secrets and validates them. It
// returns an error only for API failures; invalid input is excluded per source
// and recorded in problems so the rest still renders.
func (r *ReconcileIstio) resolveTrust(ctx context.Context, installation *operatorv1.InstallationSpec, instance *operatorv1.Istio) (*trustInputs, error) {
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

	if installation.CertificateManagement != nil {
		// Certificate management means every certificate comes from the
		// cluster's signer, which a mesh CA the operator renders would bypass.
		// Until that is supported, istiod keeps the CA it has.
		in.problems = append(in.problems, "Installation spec.certificateManagement is set, which the operator's management of the Istio CA does not support; istiod keeps signing with the CA it has")
		return in, nil
	}

	if err := r.resolveSigner(ctx, instance, in, selfSigned); err != nil {
		return nil, err
	}
	if in.userCACerts {
		// Extra anchors only reach ztunnel through a cacerts the operator renders.
		return in, nil
	}

	if err := r.resolveAdditionalAnchors(ctx, instance, in); err != nil {
		return nil, err
	}
	return in, nil
}

// resolveSigner picks the CA to render from the one istiod signs with and the
// one the CR asks for, moving between them through the signer transition when
// their roots differ. Replacing the root in one step would cut off every
// ztunnel that has not refreshed its certificate yet.
func (r *ReconcileIstio) resolveSigner(ctx context.Context, instance *operatorv1.Istio, in *trustInputs, selfSigned *corev1.Secret) error {
	recorded := istio.ReadTransition(in.current)
	current := currentSigner(in.current, selfSigned)
	if current.source == istio.CASourceUnmanaged && current.ca != nil {
		// Its root may be shared with other clusters, which would not trust an
		// operator root, and the Secret belongs to the user, so it is neither
		// replaced nor owned, whatever the CR asks for. Only the roots it signs
		// with are published.
		in.userCACerts = true
		in.ownRoots = current.roots
		if s := instance.Spec; s.CertificateAuthority != nil || (s.TrustAnchors != nil && len(s.TrustAnchors.Additional) > 0) {
			in.notice = fmt.Sprintf("Secret %s/%s was not created by the operator, so it is left as it is and "+
				"spec.certificateAuthority and spec.trustAnchors do not apply. Delete it to let the operator manage the Istio CA",
				istio.IstioNamespace, istio.CACertsSecretName)
		}
		return nil
	}
	desired, desiredSource, problem, err := r.resolveDesiredCA(ctx, instance)
	if err != nil {
		return err
	}
	if in.current == nil && current.problem == "" && desired != nil {
		if err := r.checkLostSigner(ctx, &current, desired); err != nil {
			return err
		}
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
		CurrentTrust:  current.trust,
		Desired:       desired,
		DesiredSource: desiredSource,
		Recorded:      recorded,
		Rolled:        rolled,
		Now:           r.clock(),
		Wait:          istio.SignerTransitionWait(),
	})
	in.localCA, in.source, in.transition = step.Signer, step.Source, step.Transition
	// Extra roots are configuration, not part of a signer, so they stay trusted
	// whichever CA signs in this phase.
	if step.Signer != desired {
		signs := *step.Signer
		signs.ExtraRoots = desired.ExtraRoots
		in.localCA = &signs
	}
	if step.AwaitingRoll {
		in.requeueAfter = utils.StandardRetry
	} else {
		in.requeueAfter = step.RequeueAfter
	}
	if step.Transition != nil {
		in.notice = transitionNotice(step, current.source, desiredSource, instance)
		return nil
	}
	if in.current != nil && current.source != istio.CASourceSelfSigned {
		return r.retireSelfSigned(ctx, selfSigned)
	}
	return nil
}

// retireSelfSigned marks istio-ca-secret once a cacerts signs and no
// transition still trusts its root. Without the mark, a deleted cacerts would
// bring the old self-signed CA back as the signer, and ztunnels no longer
// trust its root.
func (r *ReconcileIstio) retireSelfSigned(ctx context.Context, secret *corev1.Secret) error {
	if secret == nil || selfSignedRetired(secret) {
		return nil
	}
	fingerprints := selfSignedFingerprints(secret)
	if fingerprints == "" {
		return nil
	}
	secret = secret.DeepCopy()
	if secret.Annotations == nil {
		secret.Annotations = map[string]string{}
	}
	secret.Annotations[istio.SelfSignedCARetiredAnnotation] = fingerprints
	log.Info("Retired Istio's self-signed CA", "secret", istio.IstioNamespace+"/"+istio.IstioSelfSignedCASecretName)
	return r.Update(ctx, secret)
}

func selfSignedRetired(secret *corev1.Secret) bool {
	fingerprints := selfSignedFingerprints(secret)
	return fingerprints != "" && secret.Annotations[istio.SelfSignedCARetiredAnnotation] == fingerprints
}

func selfSignedFingerprints(secret *corev1.Secret) string {
	roots, err := istio.ParseCACertificates(secret.Data[istio.RootCertKey])
	if err != nil {
		return ""
	}
	return istio.Fingerprints(roots)
}

// checkLostSigner tells a fresh install from a mesh whose cacerts was deleted.
// Roots that this cluster publishes and neither the desired CA nor the current
// signer holds can still be all that some workloads trust. Moving on from the
// current signer would cut them off, so the signer is reported lost and nothing
// is rendered until a human restores cacerts or accepts the jump. The current
// signer may be a self-signed CA that a new istiod pod created after cacerts
// went, so its existence does not prove that nothing was lost.
func (r *ReconcileIstio) checkLostSigner(ctx context.Context, current *signer, desired *istio.CA) error {
	cm := &corev1.ConfigMap{}
	if err := r.Get(ctx, types.NamespacedName{Name: istio.TrustExportConfigMapName, Namespace: istio.IstioNamespace}, cm); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}
	published, err := istio.ParseCACertificates([]byte(cm.Data[istio.RootCertKey]))
	if err != nil {
		// What the ConfigMap published is unknown, so it is left as it is for
		// peers, and nothing is rendered that could move on from those roots.
		current.roots = nil
		current.problem = fmt.Sprintf("Secret %s/%s is missing, and ConfigMap %s/%s does not parse, so the roots it publishes are unknown: %v. "+
			"Restore the Secret, or delete the ConfigMap to move to the new root at once, which interrupts mTLS until workload certificates renew",
			istio.IstioNamespace, istio.CACertsSecretName, istio.IstioNamespace, istio.TrustExportConfigMapName, err)
		return nil
	}
	held := map[string]bool{}
	for _, c := range append(append([]*x509.Certificate{}, desired.Roots...), current.roots...) {
		held[string(c.Raw)] = true
	}
	for _, c := range published {
		if !held[string(c.Raw)] {
			current.roots = published
			current.problem = fmt.Sprintf("Secret %s/%s is missing, and ConfigMap %s/%s publishes roots the desired CA does not hold. "+
				"Restore the Secret, or delete the ConfigMap to move to the new root at once, which interrupts mTLS until workload certificates renew",
				istio.IstioNamespace, istio.CACertsSecretName, istio.IstioNamespace, istio.TrustExportConfigMapName)
			return nil
		}
	}
	return nil
}

// signer is the CA istiod signs with now.
type signer struct {
	ca     *istio.CA
	source istio.CASource
	// roots are the roots to publish; they are known even when ca did not validate.
	roots []*x509.Certificate
	// trust is every root in the bundle istiod serves, signer's or not.
	trust   []*x509.Certificate
	problem string
}

// currentSigner reads the CA istiod signs with: the one in cacerts when it
// exists, since a complete cacerts puts istiod on the plugged-CA path whoever
// made it, else the self-signed CA istiod persisted in istio-ca-secret, unless
// the operator retired it. An install with neither has no signer yet.
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
	case selfSigned != nil && !selfSignedRetired(selfSigned):
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
	// Any root with the same subject and key as the signer's own, a renewed
	// root or a trust anchor, verifies the signer too, so only the roots cacerts
	// records as the signer's count as its own.
	if own := istio.SignerRoots(cacerts); len(own) > 0 {
		if signs, err := istio.LoadCA(withRoots(secret.Data, own)); err == nil {
			ca = signs
		}
	}
	// Roots beside the signer in a bundle the operator composed belong to
	// anchors and transitions, each carried by its own source; only a customer
	// Secret's extra roots travel with its CA.
	ca.ExtraRoots = nil
	s.ca, s.roots = ca, ca.Roots
	// LoadCA has parsed this bundle already.
	s.trust, _ = istio.ParseCACertificates(istio.RootBundle(secret.Data))
	return s
}

func withRoots(data map[string][]byte, roots []*x509.Certificate) map[string][]byte {
	out := maps.Clone(data)
	out[istio.RootCertKey] = istio.EncodeCertificates(roots...)
	return out
}

// resolveDesiredCA is the CA the Istio CR asks for: a customer Secret, or the
// operator-managed CA, generated the first time. Content that does not
// validate is a problem for a human, not an error.
func (r *ReconcileIstio) resolveDesiredCA(ctx context.Context, instance *operatorv1.Istio) (ca *istio.CA, source istio.CASource, problem string, err error) {
	var name string
	if spec := instance.Spec.CertificateAuthority; spec != nil && spec.Secret != nil {
		source, name = istio.CASourceSecret, spec.Secret.Name
		ca, err = r.loadCASecret(ctx, name, istio.TrustDomain(instance))
	} else {
		source, name = istio.CASourceOperatorManaged, istio.OperatorCASecretName
		ca, err = r.ensureOperatorCA(ctx, istio.TrustDomain(instance))
	}
	switch {
	case err == nil:
	case errors.IsNotFound(err):
		problem = fmt.Sprintf("Secret %s/%s named by spec.certificateAuthority.secret does not exist", common.OperatorNamespace(), name)
		err = nil
	default:
		if _, invalid := err.(invalidCAError); invalid {
			problem = fmt.Sprintf("Secret %s/%s is not a usable CA: %v", common.OperatorNamespace(), name, err)
			err = nil
		}
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
// did not create it. It names a target CA the user brings.
func transitionNotice(step istio.TransitionStep, currentSource, desiredSource istio.CASource, instance *operatorv1.Istio) string {
	t := step.Transition
	from := ""
	if t.Phase < istio.TransitionSwitchSigner && currentSource != desiredSource {
		// The retiring user CA may live in a Secret the CR no longer names.
		from = " from " + describeCASource(currentSource, "")
	}
	to := ""
	if ca := instance.Spec.CertificateAuthority; desiredSource == istio.CASourceSecret && ca != nil && ca.Secret != nil {
		to = " to " + describeCASource(desiredSource, ca.Secret.Name)
	}
	return fmt.Sprintf("Istio CA rotation%s%s, %s", from, to, t.Phase.Describe(t.Deadline))
}

func describeCASource(source istio.CASource, secretName string) string {
	switch source {
	case istio.CASourceSelfSigned:
		return fmt.Sprintf("Istio's self-signed CA (%s/%s)", istio.IstioNamespace, istio.IstioSelfSignedCASecretName)
	case istio.CASourceUnmanaged:
		return fmt.Sprintf("a user-provided CA (%s/%s)", istio.IstioNamespace, istio.CACertsSecretName)
	case istio.CASourceSecret:
		if secretName == "" {
			return "a user-provided CA"
		}
		return fmt.Sprintf("the CA in %s/%s", common.OperatorNamespace(), secretName)
	}
	return "the operator-managed CA"
}

// invalidCAError marks Secret content that failed validation, as opposed to an
// API error, so the caller can report it and keep going.
type invalidCAError struct{ error }

func (e invalidCAError) Unwrap() error { return e.error }

func (r *ReconcileIstio) loadCASecret(ctx context.Context, name, trustDomain string) (*istio.CA, error) {
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: common.OperatorNamespace()}, secret); err != nil {
		return nil, err
	}
	if secret.Labels[istio.CASecretLabel] != "true" {
		return nil, invalidCAError{fmt.Errorf("it does not have the label %s=true, which a Secret needs before the Istio CR can use it as its CA", istio.CASecretLabel)}
	}
	ca, err := istio.LoadCA(secret.Data)
	if err != nil {
		return nil, invalidCAError{err}
	}
	if err := ca.CheckTrustDomain(trustDomain); err != nil {
		return nil, invalidCAError{err}
	}
	return ca, nil
}

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
	labels, annotations := certificatemanagement.TLSSecretMetadata(ca.CertPEM)
	secret = &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:        key.Name,
			Namespace:   key.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Type: corev1.SecretTypeOpaque,
		Data: ca.SecretData(),
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

func (r *ReconcileIstio) resolveAdditionalAnchors(ctx context.Context, instance *operatorv1.Istio, in *trustInputs) error {
	if instance.Spec.TrustAnchors == nil {
		return nil
	}
	for i, anchor := range instance.Spec.TrustAnchors.Additional {
		source := fmt.Sprintf("spec.trustAnchors.additional[%d]", i)
		var pemData []byte
		switch {
		case anchor.Secret != nil:
			name := anchor.Secret.Name
			secret := &corev1.Secret{}
			if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: common.OperatorNamespace()}, secret); err != nil {
				if !errors.IsNotFound(err) {
					return err
				}
				in.problems = append(in.problems, fmt.Sprintf("%s: Secret %s/%s does not exist", source, common.OperatorNamespace(), name))
				continue
			}
			source = fmt.Sprintf("%s (Secret %s/%s)", source, common.OperatorNamespace(), name)
			pemData = secret.Data[istio.RootCertKey]
			if len(pemData) == 0 {
				in.problems = append(in.problems, fmt.Sprintf("%s: key %s is missing", source, istio.RootCertKey))
				continue
			}
		case anchor.PEM != "":
			pemData = []byte(anchor.PEM)
		default:
			in.problems = append(in.problems, fmt.Sprintf("%s: set secret or pem", source))
			continue
		}
		roots, err := istio.ParseCACertificates(pemData)
		if err != nil {
			in.problems = append(in.problems, fmt.Sprintf("%s: %v", source, err))
			continue
		}
		in.additional = append(in.additional, roots...)
	}
	return nil
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

// enqueueForReferencedSecret maps a Secret event in the operator namespace to a
// reconcile when the Istio CR names the Secret, or it is the operator-managed
// CA. The names come from the CR, so a fixed-name watch cannot cover them.
func (r *ReconcileIstio) enqueueForReferencedSecret(ctx context.Context, obj client.Object) []reconcile.Request {
	if obj.GetNamespace() != common.OperatorNamespace() {
		return nil
	}
	instance := &operatorv1.Istio{}
	if err := r.Get(ctx, utils.DefaultInstanceKey, instance); err != nil {
		return nil
	}
	if referencedSecretNames(instance)[obj.GetName()] {
		return []reconcile.Request{{NamespacedName: utils.DefaultInstanceKey}}
	}
	return nil
}

func referencedSecretNames(instance *operatorv1.Istio) map[string]bool {
	names := map[string]bool{istio.OperatorCASecretName: true}
	if ca := instance.Spec.CertificateAuthority; ca != nil && ca.Secret != nil {
		names[ca.Secret.Name] = true
	}
	if ta := instance.Spec.TrustAnchors; ta != nil {
		for _, anchor := range ta.Additional {
			if anchor.Secret != nil {
				names[anchor.Secret.Name] = true
			}
		}
	}
	return names
}
