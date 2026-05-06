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

package commands

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/argutils"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/clientmgr"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/common"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/ipam"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s"
	libipam "github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/pkg/buildinfo"
)

func newIPAMCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ipam",
		Short: "IP address management",
	}
	cmd.AddCommand(
		newIPAMCheckCommand(),
		newIPAMReleaseCommand(),
		newIPAMShowCommand(),
		newIPAMSplitCommand(),
		newIPAMConfigureCommand(),
	)
	return cmd
}

func newIPAMCheckCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check the integrity of the IPAM datastructures",
		RunE: func(cmd *cobra.Command, args []string) error {
			config, _ := cmd.Flags().GetString("config")
			showAllIPs, _ := cmd.Flags().GetBool("show-all-ips")
			showProblemIPs, _ := cmd.Flags().GetBool("show-problem-ips")
			output, _ := cmd.Flags().GetString("output")
			kubeconfig, _ := cmd.Flags().GetString("kubeconfig")
			allowMismatch, _ := cmd.Flags().GetBool("allow-version-mismatch")

			if err := common.CheckVersionMismatch(config, allowMismatch); err != nil {
				return err
			}

			ctx := context.Background()
			client, err := clientmgr.NewClient(config)
			if err != nil {
				return err
			}

			type accessor interface {
				Backend() bapi.Client
			}
			bc := client.(accessor).Backend()

			var kubeClient *kubernetes.Clientset
			if kc, ok := bc.(*k8s.KubeClient); ok {
				kubeClient = kc.ClientSet
			} else {
				kubeConfigPath := os.Getenv("KUBECONFIG")
				if kubeconfig != "" {
					kubeConfigPath = kubeconfig
				}
				if kubeConfigPath == "" {
					return fmt.Errorf("KUBECONFIG environment variable or --kubeconfig parameter not set")
				}
				kubeConfig, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
				if err != nil {
					return err
				}
				kubeClient, err = kubernetes.NewForConfig(kubeConfig)
				if err != nil {
					return err
				}
			}

			showProblemIPs = showAllIPs || showProblemIPs

			checker := ipam.NewIPAMChecker(kubeClient, client, bc, showAllIPs, showProblemIPs, output, buildinfo.Version)
			return checker.CheckIPAM(ctx)
		},
	}
	addConfigFlag(cmd)
	cmd.Flags().Bool("show-all-ips", false, "Print all IPs that are checked.")
	cmd.Flags().Bool("show-problem-ips", false, "Print all IPs that are leaked or not allocated properly.")
	cmd.Flags().StringP("output", "o", "", "Path to output report file.")
	cmd.Flags().String("kubeconfig", "", "Path to Kubeconfig file.")
	return cmd
}

func newIPAMReleaseCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "release",
		Short: "Release a Calico assigned IP address",
		RunE: func(cmd *cobra.Command, args []string) error {
			config, _ := cmd.Flags().GetString("config")
			ip, _ := cmd.Flags().GetString("ip")
			fromReport, _ := cmd.Flags().GetStringArray("from-report")
			force, _ := cmd.Flags().GetBool("force")
			allowMismatch, _ := cmd.Flags().GetBool("allow-version-mismatch")

			if err := common.CheckVersionMismatch(config, allowMismatch); err != nil {
				return err
			}

			ctx := context.Background()
			cfg, err := clientmgr.LoadClientConfig(config)
			if err != nil {
				return err
			}
			cfg.Spec.K8sClientQPS = float32(100)

			client, err := clientmgr.NewClientFromConfig(cfg)
			if err != nil {
				return err
			}

			ipamClient := client.IPAM()

			if len(fromReport) > 0 {
				err = ipam.ReleaseFromReports(ctx, client, force, fromReport, buildinfo.Version)
				if err != nil {
					return err
				}
				fmt.Println("You may now unlock the data store.")
				return nil
			}

			if ip != "" {
				parsedIP := argutils.ValidateIP(ip)
				opt := libipam.ReleaseOptions{Address: parsedIP.String()}

				unallocatedIPs, _, err := ipamClient.ReleaseIPs(ctx, opt)
				if err != nil {
					return fmt.Errorf("error: %v", err)
				}
				if len(unallocatedIPs) != 0 {
					return fmt.Errorf("IP address %s is not assigned", parsedIP)
				}
				fmt.Printf("Successfully released IP address %s\n", parsedIP)
			}

			return nil
		},
	}
	addConfigFlag(cmd)
	cmd.Flags().String("ip", "", "IP address to release.")
	cmd.Flags().StringArray("from-report", nil, "Release all leaked addresses from the report.")
	cmd.Flags().Bool("force", false, "Force release of leaked addresses.")
	return cmd
}

func newIPAMShowCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show details of a Calico assigned IP address or overall IP usage",
		RunE: func(cmd *cobra.Command, args []string) error {
			config, _ := cmd.Flags().GetString("config")
			ip, _ := cmd.Flags().GetString("ip")
			showBlocks, _ := cmd.Flags().GetBool("show-blocks")
			showBorrowed, _ := cmd.Flags().GetBool("show-borrowed")
			showConfiguration, _ := cmd.Flags().GetBool("show-configuration")
			allowMismatch, _ := cmd.Flags().GetBool("allow-version-mismatch")

			if err := common.CheckVersionMismatch(config, allowMismatch); err != nil {
				return err
			}

			ctx := context.Background()
			client, err := clientmgr.NewClient(config)
			if err != nil {
				return err
			}

			ipamClient := client.IPAM()
			ippoolClient := client.IPPools()

			type accessor interface {
				Backend() bapi.Client
			}
			bc := client.(accessor).Backend()

			if ip != "" {
				return ipam.ShowIP(ctx, ipamClient, ip)
			} else if showBlocks {
				return ipam.ShowBlockUtilization(ctx, ipamClient, true)
			} else if showBorrowed {
				return ipam.ShowBorrowedDetails(ctx, ippoolClient, bc)
			} else if showConfiguration {
				return ipam.ShowConfiguration(ctx, ipamClient)
			}

			return ipam.ShowBlockUtilization(ctx, ipamClient, false)
		},
	}
	addConfigFlag(cmd)
	cmd.Flags().String("ip", "", "Report whether this specific IP address is in use.")
	cmd.Flags().Bool("show-blocks", false, "Show detailed information for IP blocks as well as pools.")
	cmd.Flags().Bool("show-borrowed", false, "Show detailed information for borrowed IP addresses.")
	cmd.Flags().Bool("show-configuration", false, "Show current Calico IPAM configuration.")
	return cmd
}

func newIPAMSplitCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "split NUMBER",
		Short: "Split an IP pool into the specified number of smaller IP pools",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			config, _ := cmd.Flags().GetString("config")
			cidr, _ := cmd.Flags().GetString("cidr")
			poolName, _ := cmd.Flags().GetString("name")
			allowMismatch, _ := cmd.Flags().GetBool("allow-version-mismatch")

			if err := common.CheckVersionMismatch(config, allowMismatch); err != nil {
				return err
			}

			splitNum, err := strconv.Atoi(args[0])
			if err != nil {
				return fmt.Errorf("error reading number to split IP pools into. %s is not a valid number: %v", args[0], err)
			}

			return ipam.SplitPool(context.Background(), config, cidr, poolName, splitNum)
		},
	}
	addConfigFlag(cmd)
	cmd.Flags().String("cidr", "", "CIDR of the IP pool to split.")
	cmd.Flags().String("name", "", "Name of the IP pool to split.")
	return cmd
}

func newIPAMConfigureCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "configure",
		Short: "Configure IPAM",
		RunE: func(cmd *cobra.Command, args []string) error {
			config, _ := cmd.Flags().GetString("config")
			strictAffinity, _ := cmd.Flags().GetString("strictaffinity")
			maxBlocksStr, _ := cmd.Flags().GetString("max-blocks-per-host")
			persistenceStr, _ := cmd.Flags().GetString("kubevirt-ip-persistence")
			allowMismatch, _ := cmd.Flags().GetBool("allow-version-mismatch")
			minIPReclaimAgeSeconds, _ := cmd.Flags().GetInt("min-ip-reclaim-age-seconds")

			if err := common.CheckVersionMismatch(config, allowMismatch); err != nil {
				return err
			}

			return ipam.ConfigureIPAM(context.Background(), config, strictAffinity, maxBlocksStr, persistenceStr, minIPReclaimAgeSeconds)
		},
	}
	addConfigFlag(cmd)
	cmd.Flags().String("strictaffinity", "", "Set StrictAffinity to true/false.")
	cmd.Flags().String("max-blocks-per-host", "", "Set the maximum number of blocks that can be affine to a host.")
	cmd.Flags().String("kubevirt-ip-persistence", "", "Control whether KubeVirt VMs retain persistent IP addresses (Enabled|Disabled).")
	cmd.Flags().Int("min-ip-reclaim-age-seconds", -1, "Set the maximum time between release and re-allocation of an IP address.")
	return cmd
}
