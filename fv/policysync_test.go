// +build fvtests

// Copyright (c) 2018 Tigera, Inc. All rights reserved.
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

package fv

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/projectcalico/felix/binder"
	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/libcalico-go/lib/options"

	"github.com/projectcalico/felix/dataplane/mock"
	"github.com/projectcalico/libcalico-go/lib/set"

	"github.com/projectcalico/felix/proto"

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/felix/fv/utils"
	"github.com/projectcalico/felix/fv/workload"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
)

var _ = Context("policy sync API tests", func() {

	var (
		etcd              *containers.Container
		felix             *containers.Felix
		calicoClient      client.Interface
		w                 [3]*workload.Workload
		tempDir           string
		hostMgmtCredsPath string
	)

	BeforeEach(func() {
		// Create a temporary directory to map into the container as /var/run/calico, which
		// is where we tell Felix to put the policy sync mounts and credentials.
		var err error
		tempDir, err = ioutil.TempDir("", "felixfv")
		Expect(err).NotTo(HaveOccurred())

		// Configure felix to enable the policy sync API.
		options := containers.DefaultTopologyOptions()
		options.ExtraEnvVars["FELIX_PolicySyncPathPrefix"] = "/var/run/calico"
		// To enable debug logs, uncomment these lines; watch out for timeouts caused by the
		// resulting slow down!
		// options.ExtraEnvVars["FELIX_DebugDisableLogDropping"] = "true"
		// options.FelixLogSeverity = "debug"
		options.ExtraVolumes[tempDir] = "/var/run/calico"
		options.AlphaFeaturesToEnable = apiconfig.AlphaFeatureSA + "," + apiconfig.AlphaFeatureHTTP
		felix, etcd, calicoClient = containers.StartSingleNodeEtcdTopology(options)

		// Install a default profile that allows workloads with this profile to talk to each
		// other, in the absence of any Policy.
		defaultProfile := api.NewProfile()
		defaultProfile.Name = "default"
		defaultProfile.Spec.LabelsToApply = map[string]string{"default": ""}
		defaultProfile.Spec.Egress = []api.Rule{{Action: api.Allow}}
		defaultProfile.Spec.Ingress = []api.Rule{{
			Action: api.Allow,
			Source: api.EntityRule{Selector: "default == ''"},
		}}
		_, err = calicoClient.Profiles().Create(utils.Ctx, defaultProfile, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// Create three workloads, using that profile.
		for ii := range w {
			iiStr := strconv.Itoa(ii)
			w[ii] = workload.Run(felix, "w"+iiStr, "cali1"+iiStr, "10.65.0.1"+iiStr, "8055", "tcp")
			w[ii].WorkloadEndpoint.Spec.Endpoint = "eth0"
			w[ii].WorkloadEndpoint.Spec.Orchestrator = "k8s"
			w[ii].WorkloadEndpoint.Spec.Pod = "fv-pod-" + iiStr
			w[ii].Configure(calicoClient)
		}

		hostMgmtCredsPath = filepath.Join(tempDir, binder.CredentialsSubdir)
	})

	AfterEach(func() {
		for ii := range w {
			w[ii].Stop()
		}
		felix.Stop()

		if CurrentGinkgoTestDescription().Failed {
			etcd.Exec("etcdctl", "ls", "--recursive", "/")
		}
		etcd.Stop()
	})

	AfterEach(func() {
		if tempDir != "" {
			err := os.RemoveAll(tempDir)
			Expect(err).NotTo(HaveOccurred(), "Failed to clean up temp dir")
		}
	})

	Context("with the binder", func() {

		var (
			hostWlSocketPath, containerWlSocketPath [3]string
		)

		dirNameForWorkload := func(wl *workload.Workload) string {
			return filepath.Join(binder.MountSubdir, wl.WorkloadEndpoint.Spec.Pod)
		}

		createWorkloadDirectory := func(wl *workload.Workload) (string, string) {
			dirName := dirNameForWorkload(wl)
			hostWlDir := filepath.Join(tempDir, dirName)
			os.MkdirAll(hostWlDir, 0777)
			return hostWlDir, filepath.Join("/var/run/calico", dirName)
		}

		writeCredentialsToFile := func(credentials *binder.Credentials) error {
			var attrs []byte
			attrs, err := json.Marshal(credentials)
			if err != nil {
				return err
			}

			credentialFileName := credentials.Uid + binder.CredentialsExtension

			credsFileTmp := filepath.Join(tempDir, credentialFileName)
			err = ioutil.WriteFile(credsFileTmp, attrs, 0777)
			if err != nil {
				return err
			}

			// Lazy create the credential's directory
			err = os.MkdirAll(hostMgmtCredsPath, 0777)
			if err != nil {
				return err
			}

			// Move it to the right location now.
			credsFile := filepath.Join(hostMgmtCredsPath, credentialFileName)
			return os.Rename(credsFileTmp, credsFile)
		}

		// Simulate the creation of credentials file for the workload.
		// This is the responsibility of the flex volume driver.
		sendCreate := func(wl *workload.Workload) (*binder.Credentials, error) {
			credentials := &binder.Credentials{
				Uid:       wl.WorkloadEndpoint.Spec.Pod,
				Namespace: "fv",
				Workload:  wl.WorkloadEndpoint.Spec.Pod,
			}

			err := writeCredentialsToFile(credentials)
			if err != nil {
				return nil, err
			}

			log.Info("Workload credentials written")
			return credentials, err
		}

		Context("after creating a client for each workload", func() {
			BeforeEach(func() {
				for i, wl := range w {
					// Create the workload directory, this would normally be the responsibility of the
					// flex volume driver.
					hostWlDir, containerWlDir := createWorkloadDirectory(wl)
					hostWlSocketPath[i] = filepath.Join(hostWlDir, binder.SocketFilename)
					containerWlSocketPath[i] = filepath.Join(containerWlDir, binder.SocketFilename)

					// Tell Felix about the new directory.
					_, err := sendCreate(wl)
					Expect(err).NotTo(HaveOccurred())
				}
			})

			It("felix should create the workload socket", func() {
				for _, p := range hostWlSocketPath {
					Eventually(p).Should(BeAnExistingFile())
				}
			})

			Context("with open workload connections", func() {

				// Then connect to it.
				var (
					wlConn   [3]*grpc.ClientConn
					wlClient [3]proto.PolicySyncClient
					cancel   context.CancelFunc
					ctx      context.Context
					err      error
				)

				createWorkloadConn := func(i int) (*grpc.ClientConn, proto.PolicySyncClient) {
					var opts []grpc.DialOption
					opts = append(opts, grpc.WithInsecure())
					opts = append(opts, grpc.WithDialer(unixDialer))
					var conn *grpc.ClientConn
					conn, err = grpc.Dial(hostWlSocketPath[i], opts...)
					Expect(err).NotTo(HaveOccurred())
					wlClient := proto.NewPolicySyncClient(conn)
					return conn, wlClient
				}

				BeforeEach(func() {
					ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)

					for i := range w {
						// Use the fact that anything we exec inside the Felix container runs as root to fix the
						// permissions on the socket so the test process can connect.
						Eventually(hostWlSocketPath[i]).Should(BeAnExistingFile())
						felix.Exec("chmod", "a+rw", containerWlSocketPath[i])
						wlConn[i], wlClient[i] = createWorkloadConn(i)
					}
				})

				AfterEach(func() {
					if cancel != nil {
						cancel()
					}
				})

				Context("with mock clients syncing", func() {
					var (
						mockWlClient [3]*mockWorkloadClient
					)

					BeforeEach(func() {
						for i := range w {
							client := newMockWorkloadClient(fmt.Sprintf("workload-%d", i))
							client.StartSyncing(ctx, wlClient[i])
							mockWlClient[i] = client
						}
					})

					AfterEach(func() {
						log.Info("AfterEach: cancelling main context")
						cancel()
						for _, c := range mockWlClient {
							Eventually(c.Done).Should(BeClosed())
						}
					})

					It("workload 0's client should receive correct updates", func() {
						Eventually(mockWlClient[0].InSync).Should(BeTrue())
						Eventually(mockWlClient[0].ActiveProfiles).Should(Equal(set.From(proto.ProfileID{Name: "default"})))
						// Should only hear about our own workload.
						Eventually(mockWlClient[0].EndpointToPolicyOrder).Should(Equal(
							map[string][]mock.TierInfo{"k8s/fv/fv-pod-0/eth0": {}}))
					})

					It("workload 1's client should receive correct updates", func() {
						Eventually(mockWlClient[1].InSync).Should(BeTrue())
						Eventually(mockWlClient[1].ActiveProfiles).Should(Equal(set.From(proto.ProfileID{Name: "default"})))
						// Should only hear about our own workload.
						Eventually(mockWlClient[1].EndpointToPolicyOrder).Should(Equal(
							map[string][]mock.TierInfo{"k8s/fv/fv-pod-1/eth0": {}}))
					})

					Context("after closing one client's gRPC connection", func() {
						BeforeEach(func() {
							// Sanity check that the connection is up before we close it.
							Eventually(mockWlClient[2].InSync, "10s").Should(BeTrue())

							// Close it and wait for the client to shut down.
							wlConn[2].Close()
							Eventually(mockWlClient[2].Done, "10s").Should(BeClosed())
						})

						doChurn := func(wlIndexes ...int) {
							for i := 0; i < 100; i++ {
								wlIdx := wlIndexes[i%len(wlIndexes)]
								By(fmt.Sprintf("Churn %d; targetting workload %d", i, wlIdx))

								policy := api.NewGlobalNetworkPolicy()
								policy.SetName("policy-0")
								policy.Spec.Selector = w[wlIdx].NameSelector()

								policy, err = calicoClient.GlobalNetworkPolicies().Create(ctx, policy, utils.NoOptions)
								Expect(err).NotTo(HaveOccurred())

								if wlIdx != 2 {
									policyID := proto.PolicyID{Name: "default.policy-0", Tier: "default"}
									Eventually(mockWlClient[wlIdx].ActivePolicies).Should(Equal(set.From(policyID)))
								}

								_, err = calicoClient.GlobalNetworkPolicies().Delete(ctx, "policy-0", options.DeleteOptions{})
								Expect(err).NotTo(HaveOccurred())

								if wlIdx != 2 {
									Eventually(mockWlClient[wlIdx].ActivePolicies).Should(Equal(set.New()))
								}
							}
						}

						It("churn affecting all endpoints should result in expected updates", func() {
							// Send in some churn to ensure that we exhaust any buffers that might let
							// one or two updates through.
							doChurn(0, 1, 2)
						})

						It("churn affecting only active endpoints should result in expected updates", func() {
							// Send in some churn to ensure that we exhaust any buffers that might let
							// one or two updates through.
							doChurn(0, 1)
						})
					})

					Context("after adding a policy that applies to workload 0 only", func() {
						var (
							policy   *api.GlobalNetworkPolicy
							policyID proto.PolicyID
						)

						BeforeEach(func() {
							policy = api.NewGlobalNetworkPolicy()
							policy.SetName("policy-0")
							policy.Spec.Selector = w[0].NameSelector()
							policy.Spec.Ingress = []api.Rule{
								{
									Action: "Allow",
									Source: api.EntityRule{
										Selector: "all()",
										ServiceAccounts: &api.ServiceAccountMatch{
											Selector: "foo == 'bar'",
										},
									},
								},
							}
							policy.Spec.Egress = []api.Rule{
								{
									Action: "Allow",
								},
							}
							policy, err = calicoClient.GlobalNetworkPolicies().Create(ctx, policy, utils.NoOptions)
							Expect(err).NotTo(HaveOccurred())

							policyID = proto.PolicyID{Name: "default.policy-0", Tier: "default"}
						})

						It("should be sent to workload 0 only", func() {
							Eventually(mockWlClient[0].ActivePolicies).Should(Equal(set.From(
								policyID,
							)))
							Eventually(mockWlClient[0].EndpointToPolicyOrder).Should(Equal(
								map[string][]mock.TierInfo{"k8s/fv/fv-pod-0/eth0": {{
									Name:               "default",
									EgressPolicyNames:  []string{"default.policy-0"},
									IngressPolicyNames: []string{"default.policy-0"},
								}}}))

							Consistently(mockWlClient[1].ActivePolicies).Should(Equal(set.New()))
							Consistently(mockWlClient[2].ActivePolicies).Should(Equal(set.New()))
						})

						It("should be correctly mapped to proto policy", func() {
							Eventually(mockWlClient[0].ActivePolicies).Should(Equal(set.From(
								policyID,
							)))
							policy := mockWlClient[0].ActivePolicy(policyID)
							// The rule IDs are fairly random hashes, check they're there but
							// ignore them for the comparison.
							for _, r := range policy.InboundRules {
								Expect(r.RuleId).NotTo(Equal(""))
								r.RuleId = ""
							}
							for _, r := range policy.OutboundRules {
								Expect(r.RuleId).NotTo(Equal(""))
								r.RuleId = ""
							}
							Expect(policy).To(Equal(
								&proto.Policy{
									Namespace: "", // Global policy has no namespace
									InboundRules: []*proto.Rule{
										{
											Action:              "allow",
											OriginalSrcSelector: "all()",
											SrcIpSetIds: []string{
												utils.IPSetIDForSelector("all()"),
											},
											SrcServiceAccountMatch: &proto.ServiceAccountMatch{
												Selector: "foo == 'bar'",
											},
										},
									},
									OutboundRules: []*proto.Rule{
										{
											Action: "allow",
										},
									},
								},
							))
						})

						It("should handle a deletion", func() {
							// Make sure the initial update makes it through or we might get a
							// false positive.
							Eventually(mockWlClient[0].ActivePolicies).Should(Equal(set.From(policyID)))

							_, err := calicoClient.GlobalNetworkPolicies().Delete(ctx, "policy-0", options.DeleteOptions{})
							Expect(err).NotTo(HaveOccurred())

							Eventually(mockWlClient[0].ActivePolicies).Should(Equal(set.New()))
						})

						It("should handle a change of selector", func() {
							// Make sure the initial update makes it through or we might get a
							// false positive.
							Eventually(mockWlClient[0].ActivePolicies).Should(Equal(set.From(
								policyID,
							)))

							By("Sending through an endpoint update and policy remove")
							policy.Spec.Selector = w[1].NameSelector()
							var err error
							policy, err = calicoClient.GlobalNetworkPolicies().Update(ctx, policy, options.SetOptions{})
							Expect(err).NotTo(HaveOccurred())

							Eventually(mockWlClient[0].EndpointToPolicyOrder).Should(Equal(
								map[string][]mock.TierInfo{"k8s/fv/fv-pod-0/eth0": {}}))
							Eventually(mockWlClient[0].ActivePolicies).Should(Equal(set.New()))

							By("Updating workload 1 to make the policy active")
							Eventually(mockWlClient[1].ActivePolicies).Should(Equal(set.From(policyID)))
							Eventually(mockWlClient[1].EndpointToPolicyOrder).Should(Equal(
								map[string][]mock.TierInfo{"k8s/fv/fv-pod-1/eth0": {{
									Name:               "default",
									EgressPolicyNames:  []string{"default.policy-0"},
									IngressPolicyNames: []string{"default.policy-0"},
								}}}))

							Consistently(mockWlClient[2].ActivePolicies).Should(Equal(set.New()))
						})

						It("should handle a change of profiles", func() {
							// Make sure the initial update makes it through or we might get a
							// false positive.
							defProfID := proto.ProfileID{Name: "default"}
							Eventually(mockWlClient[0].ActiveProfiles).Should(Equal(set.From(
								defProfID,
							)))
							Eventually(mockWlClient[0].EndpointToProfiles).Should(Equal(map[string][]string{
								"k8s/fv/fv-pod-0/eth0": {"default"}}))

							// Send in an endpoint update that adds one profile and deletes another.
							var err error
							w[0].WorkloadEndpoint.Spec.Profiles = []string{"notdefault"}
							w[0].WorkloadEndpoint, err = calicoClient.WorkloadEndpoints().Update(ctx, w[0].WorkloadEndpoint, options.SetOptions{})
							Expect(err).NotTo(HaveOccurred())

							By("Sending through an endpoint update and policy remove/update")
							notDefProfID := proto.ProfileID{Name: "notdefault"}
							Eventually(mockWlClient[0].EndpointToProfiles).Should(Equal(map[string][]string{
								"k8s/fv/fv-pod-0/eth0": {"notdefault"}}))
							Eventually(mockWlClient[0].ActiveProfiles).Should(Equal(set.From(notDefProfID)))

							Consistently(mockWlClient[2].ActiveProfiles).Should(Equal(set.From(defProfID)))
						})
					})

					Context("after adding a service account as profile", func() {
						var saID proto.ServiceAccountID

						BeforeEach(func() {
							log.Info("Adding Service Account Profile")
							profile := api.NewProfile()
							profile.SetName(conversion.ServiceAccountProfileNamePrefix + "sa-namespace.sa-name")
							saID.Name = "sa-name"
							saID.Namespace = "sa-namespace"
							profile.Spec.LabelsToApply = map[string]string{
								conversion.ServiceAccountLabelPrefix + "key.1": "value.1",
								conversion.ServiceAccountLabelPrefix + "key_2": "value-2",
							}
							profile, err = calicoClient.Profiles().Create(ctx, profile, utils.NoOptions)
							Expect(err).NotTo(HaveOccurred())
							log.Info("Done adding profile")
						})

						It("should sync service account to each workload", func() {
							for _, c := range mockWlClient {
								Eventually(c.ServiceAccounts).Should(Equal(map[proto.ServiceAccountID]*proto.ServiceAccountUpdate{
									saID: {
										Id:     &saID,
										Labels: map[string]string{"key.1": "value.1", "key_2": "value-2"},
									},
								}))
							}
						})
					})

					Context("after adding a namespace as profile", func() {
						var nsID proto.NamespaceID

						BeforeEach(func() {
							log.Info("Adding Namespace Profile")
							profile := api.NewProfile()
							profile.SetName(conversion.NamespaceProfileNamePrefix + "ns1")
							nsID.Name = "ns1"
							profile.Spec.LabelsToApply = map[string]string{
								conversion.NamespaceLabelPrefix + "key.1": "value.1",
								conversion.NamespaceLabelPrefix + "key_2": "value-2",
							}
							profile, err = calicoClient.Profiles().Create(ctx, profile, utils.NoOptions)
							Expect(err).NotTo(HaveOccurred())
							log.Info("Done adding profile")
						})

						It("should sync namespace to each workload", func() {
							for _, c := range mockWlClient {
								Eventually(c.Namespaces).Should(Equal(map[proto.NamespaceID]*proto.NamespaceUpdate{
									nsID: {
										Id:     &nsID,
										Labels: map[string]string{"key.1": "value.1", "key_2": "value-2"},
									},
								}))
							}
						})
					})
				})

				createExtraSyncClient := func(ctx context.Context) proto.PolicySync_SyncClient {
					syncClient, err := wlClient[0].Sync(ctx, &proto.SyncRequest{})
					Expect(err).NotTo(HaveOccurred())
					// Get something from the first connection to make sure it's up.
					_, err = syncClient.Recv()
					Expect(err).NotTo(HaveOccurred())
					return syncClient
				}

				expectFullSync := func(client *mockWorkloadClient) {
					// The new client should take over, getting a full sync.
					Eventually(client.InSync).Should(BeTrue())
					Eventually(client.ActiveProfiles).Should(Equal(set.From(proto.ProfileID{Name: "default"})))
					Eventually(client.EndpointToPolicyOrder).Should(Equal(map[string][]mock.TierInfo{"k8s/fv/fv-pod-0/eth0": {}}))
				}

				expectSyncClientErr := func(syncClient proto.PolicySync_SyncClient) {
					Eventually(func() error {
						_, err := syncClient.Recv()
						return err
					}).Should(HaveOccurred())
				}

				It("a Sync stream should get closed if a second call to Sync() call is made", func() {
					// Create first connection manually.
					syncClient := createExtraSyncClient(ctx)

					// Then create a new mock client.
					client := newMockWorkloadClient("workload-0 second client")
					client.StartSyncing(ctx, wlClient[0])

					// The new client should take over, getting a full sync.
					expectFullSync(client)

					// The old connection should get killed.
					expectSyncClientErr(syncClient)

					cancel()
					Eventually(client.Done).Should(BeClosed())
				})

				It("a Sync stream should get closed if a new Sync call is made on a new gRPC socket", func() {
					// Create first connection manually.
					syncClient := createExtraSyncClient(ctx)

					// Then create a new mock client with a new connection.
					newWlConn, newWlClient := createWorkloadConn(0)
					defer newWlConn.Close()
					client := newMockWorkloadClient("workload-0 second client")
					client.StartSyncing(ctx, newWlClient)

					// The new client should take over, getting a full sync.
					expectFullSync(client)

					// The old connection should get killed.
					expectSyncClientErr(syncClient)

					cancel()
					Eventually(client.Done).Should(BeClosed())
				})

				It("after closing the socket, a new Sync call should get a full snapshot", func() {
					client := newMockWorkloadClient("workload-0")
					client.StartSyncing(ctx, wlClient[0])

					// Workload should be sent over the API.
					Eventually(client.EndpointToPolicyOrder).Should(Equal(map[string][]mock.TierInfo{"k8s/fv/fv-pod-0/eth0": {}}))
					wlConn[0].Close()
					Eventually(client.Done).Should(BeClosed())

					// Then create a new mock client with a new connection.
					newWlConn, newWlClient := createWorkloadConn(0)
					defer newWlConn.Close()
					client = newMockWorkloadClient("workload-0 second client")
					client.StartSyncing(ctx, newWlClient)

					// The new client should take over, getting a full sync.
					expectFullSync(client)

					cancel()
					Eventually(client.Done).Should(BeClosed())
				})

				It("after closing the Sync, a new Sync call should get a full snapshot", func() {
					// Create and close first connection manually.
					clientCtx, clientCancel := context.WithCancel(ctx)
					syncClient := createExtraSyncClient(clientCtx)
					_, err := syncClient.Recv()
					Expect(err).NotTo(HaveOccurred())
					clientCancel()

					Eventually(func() error {
						_, err = syncClient.Recv()
						return err
					}).Should(HaveOccurred())

					// Then create a new mock client with a new connection.
					newWlConn, newWlClient := createWorkloadConn(0)
					defer newWlConn.Close()
					client := newMockWorkloadClient("workload-0 second client")
					client.StartSyncing(ctx, newWlClient)

					// The new client should take over, getting a full sync.
					expectFullSync(client)

					cancel()
					Eventually(client.Done).Should(BeClosed())
				})

				It("a sync client should get closed if the workload is removed", func() {
					client := newMockWorkloadClient("workload-0")
					client.StartSyncing(ctx, wlClient[0])

					// Workload should be sent over the API.
					Eventually(client.EndpointToPolicyOrder).Should(Equal(map[string][]mock.TierInfo{"k8s/fv/fv-pod-0/eth0": {}}))

					// Deleting the workload from the datastore should send a delete on the sync
					// socket and then close the connection.
					w[0].RemoveFromDatastore(calicoClient)
					Eventually(client.EndpointToPolicyOrder).Should(Equal(map[string][]mock.TierInfo{}))

					Eventually(client.Done).Should(BeClosed())
				})
			})
		})
	})
})

func unixDialer(target string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", target, timeout)
}

type mockWorkloadClient struct {
	*mock.MockDataplane
	name string
	Done chan struct{}
}

func newMockWorkloadClient(name string) *mockWorkloadClient {
	return &mockWorkloadClient{
		name:          name,
		MockDataplane: mock.NewMockDataplane(),
		Done:          make(chan struct{}),
	}
}

func (c *mockWorkloadClient) StartSyncing(ctx context.Context, policySyncClient proto.PolicySyncClient) {
	syncClient, err := policySyncClient.Sync(ctx, &proto.SyncRequest{})
	Expect(err).NotTo(HaveOccurred())
	go c.loopReadingFromAPI(ctx, syncClient)
}

func (c *mockWorkloadClient) loopReadingFromAPI(ctx context.Context, syncClient proto.PolicySync_SyncClient) {
	defer GinkgoRecover()
	defer close(c.Done)

	for ctx.Err() == nil {
		msg, err := syncClient.Recv()
		if err != nil {
			log.WithError(err).WithField("workload", c.name).Warn("Recv failed.")
			return
		}
		log.WithFields(log.Fields{"msg": msg, "name": c.name}).Info("Received workload message")

		// msg.Payload is an interface holding a pointer to one of the ToDataplane_<MsgType> structs, which in turn
		// hold the actual payload as their only field.  Since the protobuf compiler doesn't seem to generate a
		// clean way to access the payload struct, unpack it with reflection.
		ptrToPayloadWrapper := reflect.ValueOf(msg.Payload) // pointer to a ToDataplane_<MsgType>
		payloadWrapper := ptrToPayloadWrapper.Elem()        // a ToDataplane_<MsgType> struct
		payload := payloadWrapper.Field(0).Interface()      // pointer to an InSync/WorkloadEndpointUpdate/etc
		c.OnEvent(payload)
	}
}
