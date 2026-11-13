// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package istio

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// A signer transition moves istiod from the CA it signs with to the one the
// Istio CR asks for without breaking mTLS. A ztunnel learns roots only from the
// CA response it gets when it refreshes its workload certificate, at most one
// certificate TTL apart, so distributing a root and signing with it are two
// phases a full TTL apart, and so is signing with it and dropping the old root.
//
// The transition is recorded on the cacerts Secret so a restarted operator
// resumes in the same phase, and it is the same machine for every signer
// change: Istio's self-signed CA, or a cacerts the operator did not create, to
// the operator-managed one on upgrade, and a new operator-managed root.
const (
	// TransitionPhaseAnnotation holds the phase number, 1 to 4.
	TransitionPhaseAnnotation = "operator.tigera.io/istio-ca-transition-phase"
	// TransitionDeadlineAnnotation holds, in RFC 3339, when the clock phase
	// (2 or 4) ends. It is absent until istiod has rolled, which starts the clock.
	TransitionDeadlineAnnotation = "operator.tigera.io/istio-ca-transition-deadline"
	// TransitionFromAnnotation names the retiring roots and
	// TransitionToAnnotation the incoming ones, as sorted, comma-separated
	// SHA-256 fingerprints of their DER encodings; both are in root-cert.pem.
	TransitionFromAnnotation = "operator.tigera.io/istio-ca-transition-from"
	TransitionToAnnotation   = "operator.tigera.io/istio-ca-transition-to"
	// TransitionKeepAnnotation names, in the same form, the roots root-cert.pem
	// held beside the signer's when the transition started. A cacerts the
	// operator did not create may trust roots that still back certificates in
	// use, so they stay in the bundle until the transition ends.
	TransitionKeepAnnotation = "operator.tigera.io/istio-ca-transition-keep"

	// ztunnelSecretTTLEnv is ztunnel's name for its workload certificate TTL and
	// ztunnelDefaultSecretTTL its built-in default (ztunnel src/config.rs).
	ztunnelSecretTTLEnv     = "SECRET_TTL"
	ztunnelDefaultSecretTTL = 24 * time.Hour

	transitionPhaseCount = 4
)

// TransitionPhase numbers the phases of a signer transition as the design does.
type TransitionPhase int

const (
	// TransitionNone: istiod signs with the desired CA and trusts no retiring root.
	TransitionNone TransitionPhase = iota
	// TransitionDistributeRoot: the retiring CA still signs and root-cert.pem
	// carries both roots; istiod is rolling to serve it.
	TransitionDistributeRoot
	// TransitionAwaitDistribution: istiod rolled; within one TTL every ztunnel
	// has refreshed and holds both roots.
	TransitionAwaitDistribution
	// TransitionSwitchSigner: the desired CA signs; both roots stay; istiod is rolling.
	TransitionSwitchSigner
	// TransitionAwaitExpiry: istiod rolled; within one more TTL no certificate
	// from the retiring CA is valid, and its root can go.
	TransitionAwaitExpiry
)

// String is the annotation value.
func (p TransitionPhase) String() string { return strconv.Itoa(int(p)) }

// Describe says what the phase waits for, for a status message. Clock phases
// take the deadline.
func (p TransitionPhase) Describe(deadline time.Time) string {
	switch p {
	case TransitionDistributeRoot:
		return "phase 1/4: adding the new root; waiting for istiod to roll out"
	case TransitionAwaitDistribution:
		return "phase 2/4: waiting until " + deadline.UTC().Format(time.RFC3339) + " for workload certificates to renew"
	case TransitionSwitchSigner:
		return "phase 3/4: signing with the new CA; waiting for istiod to roll out"
	case TransitionAwaitExpiry:
		return "phase 4/4: waiting until " + deadline.UTC().Format(time.RFC3339) + " to remove the old root"
	}
	return ""
}

// SignerTransition is a signer change in progress, as the renderer sees it.
// Configuration.LocalCA is the signer of the phase: the retiring CA in phases 1
// and 2, the desired one in 3 and 4. Retiring and Incoming are the roots of the
// two signers; both stay in root-cert.pem and both are published for peers
// until the transition ends. Kept stays in root-cert.pem too, but is not
// published: this cluster never signed with it, and it may be another
// cluster's root.
type SignerTransition struct {
	Phase    TransitionPhase
	Deadline time.Time
	Retiring []*x509.Certificate
	Incoming []*x509.Certificate
	Kept     []*x509.Certificate
}

// annotations records the transition on cacerts.
func (t *SignerTransition) annotations() map[string]string {
	if t == nil {
		return nil
	}
	a := map[string]string{
		TransitionPhaseAnnotation: t.Phase.String(),
		TransitionFromAnnotation:  Fingerprints(t.Retiring),
		TransitionToAnnotation:    Fingerprints(t.Incoming),
	}
	if !t.Deadline.IsZero() {
		a[TransitionDeadlineAnnotation] = t.Deadline.UTC().Format(time.RFC3339)
	}
	if len(t.Kept) > 0 {
		a[TransitionKeepAnnotation] = Fingerprints(t.Kept)
	}
	return a
}

// roots are the roots the transition adds beside the signer's own.
func (t *SignerTransition) roots() []*x509.Certificate {
	if t == nil {
		return nil
	}
	return append(append([]*x509.Certificate{}, t.Retiring...), t.Incoming...)
}

// bundleRoots are the roots the transition adds to root-cert.pem.
func (t *SignerTransition) bundleRoots() []*x509.Certificate {
	if t == nil {
		return nil
	}
	return append(t.roots(), t.Kept...)
}

// TransitionState is what the cacerts Secret records of a transition: the
// phase, its deadline once the clock runs, and the retiring and incoming roots
// resolved against root-cert.pem. A root the annotations name that is not in
// the bundle is dropped, so what comes back is always something istiod serves.
type TransitionState struct {
	Phase    TransitionPhase
	Deadline time.Time
	Retiring []*x509.Certificate
	Incoming []*x509.Certificate
	Kept     []*x509.Certificate
}

// ReadTransition decodes the transition recorded on cacerts. Anything that does
// not decode reads as no transition, which the step function then rebuilds
// from the content.
func ReadTransition(cacerts *corev1.Secret) TransitionState {
	var s TransitionState
	if cacerts == nil {
		return s
	}
	a := cacerts.Annotations
	phase, err := strconv.Atoi(a[TransitionPhaseAnnotation])
	if err != nil || phase < 1 || phase > transitionPhaseCount {
		return s
	}
	s.Phase = TransitionPhase(phase)
	if deadline, err := time.Parse(time.RFC3339, a[TransitionDeadlineAnnotation]); err == nil {
		s.Deadline = deadline
	}
	roots, _ := ParseCertificates(cacerts.Data[RootCertKey])
	s.Retiring = selectByFingerprint(roots, a[TransitionFromAnnotation])
	s.Incoming = selectByFingerprint(roots, a[TransitionToAnnotation])
	s.Kept = selectByFingerprint(roots, a[TransitionKeepAnnotation])
	return s
}

// Roots are the roots a recorded transition publishes beside the signer's.
func (s TransitionState) Roots() []*x509.Certificate {
	return append(append([]*x509.Certificate{}, s.Retiring...), s.Incoming...)
}

// Fingerprint is the hex SHA-256 of the certificate's DER encoding.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// Fingerprints is the sorted, comma-separated fingerprints of the certificates.
func Fingerprints(certs []*x509.Certificate) string {
	fps := make([]string, 0, len(certs))
	for _, c := range certs {
		fps = append(fps, Fingerprint(c))
	}
	sort.Strings(fps)
	return strings.Join(fps, ",")
}

func selectByFingerprint(certs []*x509.Certificate, fingerprints string) []*x509.Certificate {
	if fingerprints == "" {
		return nil
	}
	wanted := map[string]bool{}
	for _, fp := range strings.Split(fingerprints, ",") {
		wanted[fp] = true
	}
	var out []*x509.Certificate
	for _, c := range certs {
		if wanted[Fingerprint(c)] {
			out = append(out, c)
		}
	}
	return out
}

// SignerTransitionWait is how long a transition waits after istiod rolls before
// it moves to the next phase: the ztunnel certificate TTL, since a ztunnel
// learns roots only when it refreshes its certificate. It follows the
// SECRET_TTL the operator renders on ztunnel, so lowering that is the whole
// change; without one it is ztunnel's default.
func SignerTransitionWait() time.Duration {
	for _, env := range ztunnelEnv() {
		if env.Name == ztunnelSecretTTLEnv {
			if d, err := time.ParseDuration(env.Value); err == nil && d > 0 {
				return d
			}
		}
	}
	return ztunnelDefaultSecretTTL
}

// TransitionInput is what one reconcile knows when it decides the phase.
type TransitionInput struct {
	// Current is the CA istiod signs with now and CurrentSource where it came
	// from. Nil on an install that has no CA yet.
	Current       *CA
	CurrentSource CASource
	// CurrentTrust is every root in the root-cert.pem istiod serves now.
	CurrentTrust []*x509.Certificate
	// Desired is the CA istiod is to sign with, validated, and DesiredSource
	// where it came from.
	Desired       *CA
	DesiredSource CASource
	// Recorded is what the cacerts Secret records of a transition in progress.
	Recorded TransitionState
	// Rolled is whether istiod serves the cacerts in the cluster.
	Rolled bool
	// Now is the clock and Wait how long each clock phase lasts.
	Now  time.Time
	Wait time.Duration
}

// TransitionStep is what one reconcile renders and when it has to look again.
type TransitionStep struct {
	// Signer is the CA to render as LocalCA, with its Source.
	Signer *CA
	Source CASource
	// Transition is the phase to record, nil outside a transition.
	Transition *SignerTransition
	// AwaitingRoll says the phase ends when istiod has rolled, which has to be
	// polled. RequeueAfter is the time left on a clock phase.
	AwaitingRoll bool
	RequeueAfter time.Duration
}

// StepSignerTransition decides what to render from the signer istiod runs with,
// the one it is to sign with and the phase cacerts records.
//
// A transition starts when the two signers' roots differ, and ends in the steady
// state as soon as they agree: a new intermediate under the same root needs no
// transition, and a transition whose destination turns out to be the current
// signer is simply over. In phases 1 and 2 nothing has switched yet, so a
// changed desired signer restarts from phase 1 for it. In phases 3 and 4 the
// retiring root may still back certificates in use, so a changed desired signer
// waits for the retirement to finish and its own transition starts right after.
func StepSignerTransition(in TransitionInput) TransitionStep {
	step := stepSignerTransition(in)
	if step.Transition != nil {
		step.Transition.Kept = keptRoots(in)
	}
	return step
}

// keptRoots are the roots root-cert.pem held beside the two signers' when the
// transition started. Once a transition is recorded, only the record counts:
// the bundle then holds the transition's own roots as well. A cacerts the
// operator renders holds no roots but those it is asked for, so only one it
// did not create has roots to keep.
func keptRoots(in TransitionInput) []*x509.Certificate {
	if in.Recorded.Phase != TransitionNone {
		return in.Recorded.Kept
	}
	if in.CurrentSource != CASourceUnmanaged {
		return nil
	}
	signers := map[string]bool{}
	for _, c := range append(append([]*x509.Certificate{}, in.Current.Roots...), in.Desired.Roots...) {
		signers[string(c.Raw)] = true
	}
	var kept []*x509.Certificate
	for _, c := range in.CurrentTrust {
		if !signers[string(c.Raw)] {
			signers[string(c.Raw)] = true
			kept = append(kept, c)
		}
	}
	return kept
}

func stepSignerTransition(in TransitionInput) TransitionStep {
	steady := TransitionStep{Signer: in.Desired, Source: in.DesiredSource}
	if in.Current == nil {
		return steady
	}
	same := sameRoots(in.Current.Roots, in.Desired.Roots)
	rec := in.Recorded

	switch rec.Phase {
	case TransitionDistributeRoot, TransitionAwaitDistribution:
		if same {
			return steady
		}
		if !sameRoots(rec.Incoming, in.Desired.Roots) {
			return distributeRoot(in)
		}
		if !rec.Deadline.IsZero() {
			if in.Now.Before(rec.Deadline) {
				return awaitDistribution(in, rec.Deadline)
			}
			return switchSigner(in)
		}
		if in.Rolled {
			return awaitDistribution(in, in.Now.Add(in.Wait))
		}
		return distributeRoot(in)

	case TransitionSwitchSigner, TransitionAwaitExpiry:
		if len(rec.Retiring) == 0 {
			break
		}
		signer, source := in.Current, in.CurrentSource
		if same {
			signer, source = in.Desired, in.DesiredSource
		}
		if !rec.Deadline.IsZero() {
			if in.Now.Before(rec.Deadline) {
				return awaitExpiry(in, signer, source, rec.Retiring, rec.Deadline)
			}
			if same {
				return steady
			}
			return distributeRoot(in)
		}
		if in.Rolled {
			return awaitExpiry(in, signer, source, rec.Retiring, in.Now.Add(in.Wait))
		}
		return TransitionStep{
			Signer:       signer,
			Source:       source,
			Transition:   &SignerTransition{Phase: TransitionSwitchSigner, Retiring: rec.Retiring, Incoming: signer.Roots},
			AwaitingRoll: true,
		}
	}

	if same {
		return steady
	}
	return distributeRoot(in)
}

func distributeRoot(in TransitionInput) TransitionStep {
	return TransitionStep{
		Signer:       in.Current,
		Source:       in.CurrentSource,
		Transition:   &SignerTransition{Phase: TransitionDistributeRoot, Retiring: in.Current.Roots, Incoming: in.Desired.Roots},
		AwaitingRoll: true,
	}
}

func awaitDistribution(in TransitionInput, deadline time.Time) TransitionStep {
	return TransitionStep{
		Signer:       in.Current,
		Source:       in.CurrentSource,
		Transition:   &SignerTransition{Phase: TransitionAwaitDistribution, Deadline: deadline, Retiring: in.Current.Roots, Incoming: in.Desired.Roots},
		RequeueAfter: deadline.Sub(in.Now),
	}
}

func switchSigner(in TransitionInput) TransitionStep {
	return TransitionStep{
		Signer:       in.Desired,
		Source:       in.DesiredSource,
		Transition:   &SignerTransition{Phase: TransitionSwitchSigner, Retiring: in.Current.Roots, Incoming: in.Desired.Roots},
		AwaitingRoll: true,
	}
}

func awaitExpiry(in TransitionInput, signer *CA, source CASource, retiring []*x509.Certificate, deadline time.Time) TransitionStep {
	return TransitionStep{
		Signer:       signer,
		Source:       source,
		Transition:   &SignerTransition{Phase: TransitionAwaitExpiry, Deadline: deadline, Retiring: retiring, Incoming: signer.Roots},
		RequeueAfter: deadline.Sub(in.Now),
	}
}

// sameRoots reports whether the two sets hold the same certificates by DER.
func sameRoots(a, b []*x509.Certificate) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	set := map[string]bool{}
	for _, c := range a {
		set[string(c.Raw)] = true
	}
	for _, c := range b {
		if !set[string(c.Raw)] {
			return false
		}
	}
	other := map[string]bool{}
	for _, c := range b {
		other[string(c.Raw)] = true
	}
	for _, c := range a {
		if !other[string(c.Raw)] {
			return false
		}
	}
	return true
}
