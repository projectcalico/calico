// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package istio_test

import (
	"crypto/x509"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	rmeta "github.com/projectcalico/calico/operator/pkg/render/common/meta"
	"github.com/projectcalico/calico/operator/pkg/render/istio"
)

// rootCA loads a self-signed test certificate as a CA.
func rootCA(c *testCert) *istio.CA {
	ca, err := istio.LoadCA(map[string][]byte{istio.CACertKey: c.certPEM, istio.CAKeyKey: c.keyPEM, istio.RootCertKey: c.certPEM})
	Expect(err).NotTo(HaveOccurred())
	return ca
}

func certsOf(tcs ...*testCert) []*x509.Certificate {
	out := make([]*x509.Certificate, 0, len(tcs))
	for _, tc := range tcs {
		out = append(out, tc.cert)
	}
	return out
}

var _ = Describe("Istio CA signer transition", func() {
	var (
		oldRoot, newRoot *testCert
		current, desired *istio.CA
		now              time.Time
		wait             time.Duration
	)

	BeforeEach(func() {
		oldRoot, newRoot = newTestCert("old", nil, true), newTestCert("new", nil, true)
		current, desired = rootCA(oldRoot), rootCA(newRoot)
		now = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
		wait = istio.SignerTransitionWait()
	})

	It("waits one ztunnel certificate TTL, ztunnel's default while the operator renders no SECRET_TTL", func() {
		Expect(istio.SignerTransitionWait()).To(Equal(24 * time.Hour))
	})

	Describe("StepSignerTransition", func() {
		step := func(recorded istio.TransitionState, rolled bool) istio.TransitionStep {
			return istio.StepSignerTransition(istio.TransitionInput{
				Current: current, CurrentSource: istio.CASourceSelfSigned,
				Desired: desired, DesiredSource: istio.CASourceOperatorManaged,
				Recorded: recorded, Rolled: rolled, Now: now, Wait: wait,
			})
		}
		recorded := func(phase istio.TransitionPhase, deadline time.Time) istio.TransitionState {
			return istio.TransitionState{Phase: phase, Deadline: deadline, Retiring: current.Roots, Incoming: desired.Roots}
		}

		expectSteady := func(s istio.TransitionStep) {
			Expect(s.Signer).To(BeIdenticalTo(desired))
			Expect(s.Source).To(Equal(istio.CASourceOperatorManaged))
			Expect(s.Transition).To(BeNil())
			Expect(s.AwaitingRoll).To(BeFalse())
			Expect(s.RequeueAfter).To(BeZero())
		}
		expectPhase := func(s istio.TransitionStep, phase istio.TransitionPhase, signer *istio.CA) {
			Expect(s.Signer).To(BeIdenticalTo(signer))
			Expect(s.Transition).NotTo(BeNil())
			Expect(s.Transition.Phase).To(Equal(phase))
			Expect(s.Transition.Retiring).To(Equal(current.Roots))
			Expect(s.Transition.Incoming).To(Equal(desired.Roots))
		}
		expectAwaitingRoll := func(s istio.TransitionStep) {
			Expect(s.AwaitingRoll).To(BeTrue())
			Expect(s.RequeueAfter).To(BeZero())
			Expect(s.Transition.Deadline).To(BeZero())
		}
		expectClock := func(s istio.TransitionStep, deadline time.Time) {
			Expect(s.AwaitingRoll).To(BeFalse())
			Expect(s.Transition.Deadline).To(Equal(deadline))
			Expect(s.RequeueAfter).To(Equal(deadline.Sub(now)))
		}

		It("renders the desired CA straight away on an install with no signer yet", func() {
			s := istio.StepSignerTransition(istio.TransitionInput{Desired: desired, DesiredSource: istio.CASourceOperatorManaged, Now: now, Wait: wait})
			expectSteady(s)
		})

		It("needs no transition for a new intermediate under the root istiod already signs with", func() {
			intermediate := newTestCert("intermediate", oldRoot, true)
			desired, err := istio.LoadCA(map[string][]byte{istio.CACertKey: intermediate.certPEM, istio.CAKeyKey: intermediate.keyPEM, istio.RootCertKey: oldRoot.certPEM})
			Expect(err).NotTo(HaveOccurred())
			s := istio.StepSignerTransition(istio.TransitionInput{Current: current, Desired: desired, DesiredSource: istio.CASourceOperatorManaged, Now: now, Wait: wait})
			Expect(s.Signer).To(BeIdenticalTo(desired))
			Expect(s.Transition).To(BeNil())
		})

		It("starts at phase 1 when the roots differ: the current CA signs and waits for istiod to roll", func() {
			s := step(istio.TransitionState{}, true)
			expectPhase(s, istio.TransitionDistributeRoot, current)
			Expect(s.Source).To(Equal(istio.CASourceSelfSigned))
			expectAwaitingRoll(s)
		})

		It("starts no clock in phase 1 until istiod has rolled", func() {
			s := step(recorded(istio.TransitionDistributeRoot, time.Time{}), false)
			expectPhase(s, istio.TransitionDistributeRoot, current)
			expectAwaitingRoll(s)
		})

		It("moves to phase 2 with a deadline one TTL after the roll", func() {
			s := step(recorded(istio.TransitionDistributeRoot, time.Time{}), true)
			expectPhase(s, istio.TransitionAwaitDistribution, current)
			expectClock(s, now.Add(wait))
		})

		It("holds phase 2 and requeues for the time left on its deadline", func() {
			deadline := now.Add(3 * time.Hour)
			s := step(recorded(istio.TransitionAwaitDistribution, deadline), false)
			expectPhase(s, istio.TransitionAwaitDistribution, current)
			expectClock(s, deadline)
		})

		It("switches the signer at the phase 2 deadline and keeps both roots", func() {
			s := step(recorded(istio.TransitionAwaitDistribution, now), false)
			expectPhase(s, istio.TransitionSwitchSigner, desired)
			Expect(s.Source).To(Equal(istio.CASourceOperatorManaged))
			expectAwaitingRoll(s)
		})

		It("restarts from phase 1 when the desired signer changes before the switch", func() {
			other := rootCA(newTestCert("other", nil, true))
			rec := istio.TransitionState{Phase: istio.TransitionAwaitDistribution, Deadline: now.Add(time.Hour), Retiring: current.Roots, Incoming: other.Roots}
			s := step(rec, true)
			expectPhase(s, istio.TransitionDistributeRoot, current)
			expectAwaitingRoll(s)
		})

		It("restarts from phase 1 when the recorded incoming root is not in the bundle any more", func() {
			rec := istio.TransitionState{Phase: istio.TransitionAwaitDistribution, Deadline: now, Retiring: current.Roots}
			s := step(rec, true)
			expectPhase(s, istio.TransitionDistributeRoot, current)
		})

		It("ends a transition whose destination is the CA already signing", func() {
			desired = current
			s := step(recorded(istio.TransitionAwaitDistribution, now.Add(time.Hour)), true)
			expectSteady(s)
		})

		It("keeps the other roots of a cacerts the operator did not create until the transition ends, and records them", func() {
			extra := newTestCert("extra", nil, true).cert
			in := istio.TransitionInput{
				Current: current, CurrentSource: istio.CASourceUnmanaged, CurrentTrust: append(certsOf(oldRoot), extra),
				Desired: desired, DesiredSource: istio.CASourceOperatorManaged,
				Rolled: true, Now: now, Wait: wait,
			}
			s := istio.StepSignerTransition(in)
			Expect(s.Transition.Phase).To(Equal(istio.TransitionDistributeRoot))
			Expect(s.Transition.Kept).To(Equal([]*x509.Certificate{extra}))

			rendered := in
			rendered.CurrentSource = istio.CASourceOperatorManaged
			Expect(istio.StepSignerTransition(rendered).Transition.Kept).To(BeEmpty())

			// The bundle now holds the transition's roots too; only the record counts.
			in.Current, in.CurrentTrust = desired, append(certsOf(oldRoot, newRoot), extra)
			in.Recorded = istio.TransitionState{Phase: istio.TransitionAwaitExpiry, Deadline: now.Add(time.Hour), Retiring: current.Roots, Incoming: desired.Roots, Kept: []*x509.Certificate{extra}}
			s = istio.StepSignerTransition(in)
			Expect(s.Transition.Phase).To(Equal(istio.TransitionAwaitExpiry))
			Expect(s.Transition.Kept).To(Equal([]*x509.Certificate{extra}))

			in.Recorded.Deadline = now.Add(-time.Second)
			Expect(istio.StepSignerTransition(in).Transition).To(BeNil())
		})

		It("keeps a root the bundle trusted before the transition, even the destination's, when the destination changes", func() {
			in := istio.TransitionInput{
				Current: current, CurrentSource: istio.CASourceUnmanaged, CurrentTrust: certsOf(oldRoot, newRoot),
				Desired: desired, DesiredSource: istio.CASourceOperatorManaged,
				Rolled: true, Now: now, Wait: wait,
			}
			s := istio.StepSignerTransition(in)
			Expect(s.Transition.Kept).To(Equal(certsOf(newRoot)))

			third := rootCA(newTestCert("third", nil, true))
			in.Desired = third
			in.Recorded = istio.TransitionState{Phase: istio.TransitionDistributeRoot, Retiring: current.Roots, Incoming: desired.Roots, Kept: certsOf(newRoot)}
			s = istio.StepSignerTransition(in)
			Expect(s.Transition.Incoming).To(Equal(third.Roots))
			Expect(s.Transition.Kept).To(Equal(certsOf(newRoot)))
		})

		Context("after the switch, when cacerts already signs with the desired CA", func() {
			var retiring []*x509.Certificate

			BeforeEach(func() {
				retiring = current.Roots
				current = desired
			})

			rec := func(phase istio.TransitionPhase, deadline time.Time) istio.TransitionState {
				return istio.TransitionState{Phase: phase, Deadline: deadline, Retiring: retiring, Incoming: desired.Roots}
			}
			expectRetiring := func(s istio.TransitionStep, phase istio.TransitionPhase) {
				Expect(s.Signer).To(BeIdenticalTo(desired))
				Expect(s.Transition.Phase).To(Equal(phase))
				Expect(s.Transition.Retiring).To(Equal(retiring))
				Expect(s.Transition.Incoming).To(Equal(desired.Roots))
			}

			It("holds phase 3 with the retiring root until istiod has rolled", func() {
				s := step(rec(istio.TransitionSwitchSigner, time.Time{}), false)
				expectRetiring(s, istio.TransitionSwitchSigner)
				expectAwaitingRoll(s)
			})

			It("moves to phase 4 with a deadline one TTL after the roll", func() {
				s := step(rec(istio.TransitionSwitchSigner, time.Time{}), true)
				expectRetiring(s, istio.TransitionAwaitExpiry)
				expectClock(s, now.Add(wait))
			})

			It("holds phase 4 until its deadline", func() {
				deadline := now.Add(time.Hour)
				s := step(rec(istio.TransitionAwaitExpiry, deadline), true)
				expectRetiring(s, istio.TransitionAwaitExpiry)
				expectClock(s, deadline)
			})

			It("drops the retiring root at the phase 4 deadline", func() {
				expectSteady(step(rec(istio.TransitionAwaitExpiry, now.Add(-time.Second)), true))
			})

			It("treats a record whose retiring root is gone from the bundle as finished", func() {
				expectSteady(step(istio.TransitionState{Phase: istio.TransitionAwaitExpiry, Deadline: now.Add(time.Hour), Incoming: desired.Roots}, true))
			})

			Context("and the desired signer changes again", func() {
				var third *istio.CA

				BeforeEach(func() {
					third = rootCA(newTestCert("third", nil, true))
					desired = third
				})

				It("finishes retiring the old root first, signing with the CA cacerts holds", func() {
					deadline := now.Add(time.Hour)
					s := istio.StepSignerTransition(istio.TransitionInput{
						Current: current, CurrentSource: istio.CASourceOperatorManaged,
						Desired: third, DesiredSource: istio.CASourceOperatorManaged,
						Recorded: istio.TransitionState{Phase: istio.TransitionAwaitExpiry, Deadline: deadline, Retiring: retiring, Incoming: current.Roots},
						Rolled:   true, Now: now, Wait: wait,
					})
					Expect(s.Signer).To(BeIdenticalTo(current))
					Expect(s.Source).To(Equal(istio.CASourceOperatorManaged))
					Expect(s.Transition.Phase).To(Equal(istio.TransitionAwaitExpiry))
					Expect(s.Transition.Retiring).To(Equal(retiring))
					Expect(s.Transition.Incoming).To(Equal(current.Roots))
					expectClock(s, deadline)
				})

				It("starts the next transition at phase 1 as soon as the old root is dropped", func() {
					s := istio.StepSignerTransition(istio.TransitionInput{
						Current: current, CurrentSource: istio.CASourceOperatorManaged,
						Desired: third, DesiredSource: istio.CASourceOperatorManaged,
						Recorded: istio.TransitionState{Phase: istio.TransitionAwaitExpiry, Deadline: now, Retiring: retiring, Incoming: current.Roots},
						Rolled:   true, Now: now, Wait: wait,
					})
					Expect(s.Signer).To(BeIdenticalTo(current))
					Expect(s.Transition.Phase).To(Equal(istio.TransitionDistributeRoot))
					Expect(s.Transition.Retiring).To(Equal(current.Roots))
					Expect(s.Transition.Incoming).To(Equal(third.Roots))
					expectAwaitingRoll(s)
				})
			})
		})
	})

	Describe("ReadTransition", func() {
		var cacerts *corev1.Secret
		var extra *testCert

		BeforeEach(func() {
			extra = newTestCert("extra", nil, true)
			cacerts = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
					istio.TransitionPhaseAnnotation:    "2",
					istio.TransitionDeadlineAnnotation: "2026-10-31T12:00:00Z",
					istio.TransitionFromAnnotation:     istio.Fingerprints(current.Roots),
					istio.TransitionToAnnotation:       istio.Fingerprints(desired.Roots),
				}},
				Data: map[string][]byte{istio.RootCertKey: istio.ComposeRootBundle(current.Roots, desired.Roots, certsOf(extra))},
			}
		})

		It("decodes the phase, the deadline and the roots named by fingerprint", func() {
			s := istio.ReadTransition(cacerts)
			Expect(s.Phase).To(Equal(istio.TransitionAwaitDistribution))
			Expect(s.Deadline).To(Equal(time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)))
			Expect(s.Retiring).To(HaveLen(1))
			Expect(s.Retiring[0].Raw).To(Equal(oldRoot.cert.Raw))
			Expect(s.Incoming).To(HaveLen(1))
			Expect(s.Incoming[0].Raw).To(Equal(newRoot.cert.Raw))
			Expect(s.Roots()).To(HaveLen(2))
			Expect(s.Kept).To(BeEmpty())
		})

		It("decodes the kept roots, which are not among the roots it publishes", func() {
			cacerts.Annotations[istio.TransitionKeepAnnotation] = istio.Fingerprint(extra.cert)
			s := istio.ReadTransition(cacerts)
			Expect(s.Kept).To(HaveLen(1))
			Expect(s.Kept[0].Raw).To(Equal(extra.cert.Raw))
			Expect(s.Roots()).To(HaveLen(2))
		})

		It("reads no transition from a Secret without one, or with a phase that does not decode", func() {
			Expect(istio.ReadTransition(nil)).To(Equal(istio.TransitionState{}))
			Expect(istio.ReadTransition(&corev1.Secret{})).To(Equal(istio.TransitionState{}))
			for _, bad := range []string{"0", "5", "two", ""} {
				cacerts.Annotations[istio.TransitionPhaseAnnotation] = bad
				Expect(istio.ReadTransition(cacerts)).To(Equal(istio.TransitionState{}), "phase %q", bad)
			}
		})

		It("leaves the deadline zero before the clock starts and drops roots not in the bundle", func() {
			delete(cacerts.Annotations, istio.TransitionDeadlineAnnotation)
			cacerts.Annotations[istio.TransitionToAnnotation] = istio.Fingerprint(newTestCert("elsewhere", nil, true).cert)
			s := istio.ReadTransition(cacerts)
			Expect(s.Deadline).To(BeZero())
			Expect(s.Retiring).To(HaveLen(1))
			Expect(s.Incoming).To(BeEmpty())
		})
	})

	Describe("IstiodRolledOut", func() {
		var (
			cacerts *corev1.Secret
			istiod  *appsv1.Deployment
		)

		BeforeEach(func() {
			cacerts = &corev1.Secret{Data: map[string][]byte{istio.CACertKey: oldRoot.certPEM}}
			istiod = &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Generation: 3},
				Spec: appsv1.DeploymentSpec{
					Replicas: ptr.To[int32](2),
					Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
						istio.CACertsHashAnnotation: rmeta.SecretsAnnotationHash(cacerts),
					}}},
				},
				Status: appsv1.DeploymentStatus{ObservedGeneration: 3, Replicas: 2, UpdatedReplicas: 2, AvailableReplicas: 2},
			}
		})

		It("is true once the whole Deployment runs the template carrying the cacerts hash", func() {
			Expect(istio.IstiodRolledOut(istiod, cacerts)).To(BeTrue())
		})

		It("takes a nil replica count as one", func() {
			istiod.Spec.Replicas = nil
			istiod.Status = appsv1.DeploymentStatus{ObservedGeneration: 3, Replicas: 1, UpdatedReplicas: 1, AvailableReplicas: 1}
			Expect(istio.IstiodRolledOut(istiod, cacerts)).To(BeTrue())
		})

		DescribeTable("is false while the roll is incomplete or for another bundle",
			func(change func()) {
				change()
				Expect(istio.IstiodRolledOut(istiod, cacerts)).To(BeFalse())
			},
			Entry("template carries another hash", func() { istiod.Spec.Template.Annotations[istio.CACertsHashAnnotation] = "stale" }),
			Entry("template carries no hash", func() { istiod.Spec.Template.Annotations = nil }),
			Entry("template not yet observed", func() { istiod.Status.ObservedGeneration = 2 }),
			Entry("not every replica updated", func() { istiod.Status.UpdatedReplicas = 1 }),
			Entry("old replicas pending termination", func() { istiod.Status.Replicas = 3 }),
			Entry("updated replicas not available", func() { istiod.Status.AvailableReplicas = 1 }),
			Entry("nothing available", func() {
				istiod.Spec.Replicas = ptr.To[int32](0)
				istiod.Status = appsv1.DeploymentStatus{ObservedGeneration: 3}
			}),
			Entry("no Deployment", func() { istiod = nil }),
			Entry("no cacerts", func() { cacerts = nil }),
		)
	})
})
