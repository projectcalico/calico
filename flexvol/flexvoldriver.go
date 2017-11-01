package main

import (
	"errors"
	"encoding/json"
        "fmt"
	"log"
	"log/syslog"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

        pb "github.com/colabsaumoh/proto-udsuspver/udsver_v1"
	nagent "github.com/colabsaumoh/proto-udsuspver/nodeagentmgmt"
)


type Resp struct {
	Status string `json:"status"`
	Message string `json:"message"`
	// Capability resp.
	Attach bool `json:"attach,omitempty"`
	// Is attached resp.
	Attached bool `json:"attached,omitempty"`
	// Dev mount resp.
	Device string `json:"device,omitempty"`
	// Volumen name resp.
	VolumeName string `json:"volumename,omitempty"`
}

type NodeAgentInputs struct {
	Uid		string `json:"kubernetes.io/pod.uid"`
	Name		string `json:"kubernetes.io/pod.name"`
	Namespace string `json:"kubernetes.io/pod.namespace"`
	ServiceAccount	string `json:"kubernetes.io/serviceAccount.name"`
}

const (
	volumeName		string = "tmpfs"
	NodeAgentMgmtAPI	string = "/tmp/udsuspver/mgmt.sock"
	NodeAgentUdsHome	string = "/tmp/nodeagent"
)

var (
	logWrt	*syslog.Writer

	RootCmd = &cobra.Command{
		Use: "flexvoldrv",
	        Short: "Flex volume driver interface for Node Agent.",
		Long: "Flex volume driver interface for Node Agent.",
	}

	InitCmd = &cobra.Command{
		Use: "init",
		Short: "Flex volume init command.",
		Long: "Flex volume init command.",
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) != 0 {
				return fmt.Errorf("init takes no arguments.")
			}
			return Init()
		},
	}

	AttachCmd = &cobra.Command{
		Use: "attach",
		Short: "Flex volumen attach command.",
		Long: "Flex volumen attach command.",
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) < 1 || len(args) > 2 {
				return fmt.Errorf("attach takes at most 2 args.")
			}
			return Attach(args[0], args[1])
		},
	}

	DetachCmd = &cobra.Command{
		Use: "detach",
		Short: "Flex volume detach command.",
		Long: "Flex volume detach command.",
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("detach takes at least 1 arg.")
			}
			return Detach(args[0])
		},
	}

	WaitAttachCmd = &cobra.Command{
		Use: "waitforattach",
		Short: "Flex volume waitforattach command.",
		Long: "Flex volume waitforattach command.",
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) < 2 {
				return fmt.Errorf("waitforattach takes at least 2 arg.")
			}
			return WaitAttach(args[0], args[1])
		},
	}

	IsAttachedCmd = &cobra.Command{
		Use: "isattached",
		Short: "Flex volume isattached command.",
		Long: "Flex volume isattached command.",
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) < 2 {
				return fmt.Errorf("isattached takes at least 2 arg.")
			}
			return IsAttached(args[0], args[1])
		},
	}

	MountDevCmd = &cobra.Command{
		Use: "mountdevice",
		Short: "Flex volume unmount command.",
		Long: "Flex volume unmount command.",
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) < 3 {
				return fmt.Errorf("mountdevice takes 3 args.")
			}
			return MountDev(args[0], args[1], args[2])
		},
	}

	UnmountDevCmd = &cobra.Command{
		Use: "unmountdevice",
		Short: "Flex volume unmount command.",
		Long: "Flex volume unmount command.",
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("unmountdevice takes 1 arg.")
			}
			return UnmountDev(args[0])
		},
	}

	MountCmd = &cobra.Command{
		Use: "mount",
		Short: "Flex volume unmount command.",
		Long: "Flex volume unmount command.",
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) < 2 {
				return fmt.Errorf("mount takes 2 args.")
			}
			return Mount(args[0], args[1])
		},
	}

	UnmountCmd = &cobra.Command{
		Use: "unmount",
		Short: "Flex volume unmount command.",
		Long: "Flex volume unmount command.",
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("mount takes 1 args.")
			}
			return Unmount(args[0])
		},
	}

	GetVolNameCmd = &cobra.Command{
		Use: "getvolumename",
		Short: "Flex volume getvolumename command.",
		Long: "Flex volume getvolumename command.",
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("mount takes 1 args.")
			}
			return GetVolName(args[0])
		},
	}

)

func getNewVolume() string {
	return volumeName
}

func Init() error {
	return genericSucc("init", "", "Init ok.")
}

func Attach(opts, nodeName string) error {
	devId := getNewVolume()
	resp, err := json.Marshal(&Resp{Device: devId, Status: "Success", Message: "Dir created" })
	if err != nil {
		return err
	}
	fmt.Println(string(resp))
	inp := opts + "|" + nodeName
	appendToFile("attach", inp, string(resp))
	return nil
}

func Detach(devId string) error {
	resp, err := json.Marshal(&Resp{Status: "Success", Message: "Gone " + devId})
	if err != nil {
		fmt.Println(err)
		return err
	}
	fmt.Println(string(resp))
	appendToFile("detach", devId, string(resp))
	return nil
}

func WaitAttach(dev, opts string) error {
	resp, err := json.Marshal(&Resp{Device: dev, Status: "Success", Message: "Wait ok"})
	if err != nil {
		return err
	}
	fmt.Println(string(resp))
	inp := dev + "|" + opts
	appendToFile("waitattach", inp, string(resp))
	return nil
}

func IsAttached(opts, node string) error {
	resp, err := json.Marshal(&Resp{Attached: true, Status:"Success", Message: "Is attached"})
	if err != nil {
		return err
	}
	sResp := string(resp)
	fmt.Println(sResp)
	inp := opts + "|" + node
	appendToFile("isattached", inp, sResp)
	return nil
}

func MountDev(dir, dev, opts string) error {
	inp := dir + "|" + dev + "|" + opts
	return genericSucc("mountdev", inp, "Mount dev ok.")
}

func UnmountDev(dev string) error {
	return genericSucc("unmountdev", dev, "Unmount dev ok.")
}

// checkValidMountOpts checks if there are sufficient inputs to 
// call Nodeagent.
func checkValidMountOpts(opts string) (*pb.WorkloadInfo, bool) {
	ninputs := NodeAgentInputs{}
	err := json.Unmarshal([]byte(opts), &ninputs)
	if err != nil {
		return nil, false
	}

	wlInfo := pb.WorkloadInfo{Uid: ninputs.Uid,
				  Workload: ninputs.Name,
				  Namespace: ninputs.Namespace,
				  Serviceaccount: ninputs.ServiceAccount}
	return &wlInfo, true
}

func doMount(dstDir string, ninputs *pb.WorkloadInfo) error {
	newDir := NodeAgentUdsHome + "/" + ninputs.Uid
	err := os.MkdirAll(newDir, 0777)
	if err != nil {
		return err
	}

	// Do a bind mount
	cmd := exec.Command("/bin/mount", "--bind", newDir, dstDir)
	err = cmd.Run()
	if err != nil {
		return err
	}

	return nil
}

func doUnmount(dir string) error {
	cmd := exec.Command("/bin/umount", dir)
	err := cmd.Run()
	if err != nil {
		return err
	}

	return nil
}

func Mount(dir, opts string) error {
	inp := dir + "|" + opts

	ninputs, s := checkValidMountOpts(opts)
	if s == false {
		return Failure("mount", inp, "Incomplete inputs")
	}

	if err := doMount(dir, ninputs); err != nil {
		sErr := "Failure to mount: " + err.Error()
		return Failure("mount", inp, sErr)
	}

	if err := AddListener(ninputs); err != nil {
		sErr := "Failure to notify nodeagent: " + err.Error()
		return Failure("mount", inp, sErr)
	}

	return genericSucc("mount", inp, "Mount ok.")
}

func Unmount(dir string) error {
	// TBD: https://github.com/kubernetes/kubernetes/blob/61ac9d46382884a8bd9e228da22bca5817f6d226/pkg/util/mount/mount_linux.go
	// This is a bug and therefore unmount is not called.
	doUnmount(dir)

	// Does not matter what happened at doUnmount.
	// Stop the listener.
	// /var/lib/kubelet/pods/20154c76-bf4e-11e7-8a7e-080027631ab3/volumes/nodeagent~uds/test-volume/
	comps := strings.Split(dir, "/")
	if len(comps) < 5 {
		sErr := fmt.Sprintf("Failure to notify nodeagent dir %v", dir)
		return Failure("unmount", dir, sErr)
	}

	naInp := &pb.WorkloadInfo{Uid: comps[4]}
	if err := DelListener(naInp); err != nil {
		sErr := "Failure to notify nodeagent: " + err.Error()
		return Failure("unmount", dir, sErr)
	}

	return genericSucc("unmount", dir, "Unmount ok.")
}

func GetVolName(opts string) error {
	devName := getNewVolume()
	resp, err := json.Marshal(&Resp{VolumeName: devName, Status:"Success", Message: "ok"})
	if err != nil {
		return err
	}

	sResp := string(resp)
	fmt.Println(sResp)
	appendToFile("getvolname", opts, sResp)
	return nil
}

func genericSucc(caller, inp, msg string) error {
	resp, err := json.Marshal(&Resp{Status: "Success", Message: msg})
	if err != nil {
		return err
	}
	fmt.Println(string(resp))
	appendToFile(caller, inp, string(resp))
	return nil
}

func Failure(caller, inp, msg string) error {
	resp, err  := json.Marshal(&Resp{Status: "Failure", Message: msg})
	if err != nil {
		return err
	}

	sResp := string(resp)
	fmt.Println(sResp)
	appendToFile(caller, inp, sResp)
	return nil
}

func appendToFile(caller, inp, opts string) {
	if logWrt == nil {
		return
	}

	op := caller + "|"
	op = op + inp + "|"
	op = op + opts

	logWrt.Warning(op)
}

func AddListener(ninputs *pb.WorkloadInfo) error {
	client := nagent.ClientUds(NodeAgentMgmtAPI)
	if client == nil {
		return errors.New("Failed to create Nodeagent client.")
	}

	_, err := client.AddListener(ninputs)
	if err != nil {
		return err
	}

	client.Close()

	return nil
}

func DelListener(ninputs *pb.WorkloadInfo) error {
	client := nagent.ClientUds(NodeAgentMgmtAPI)
	if client == nil {
		return errors.New("Failed to create Nodeagent client.")
	}

	_, err := client.DelListener(ninputs)
	if err != nil {
		return err
	}

	client.Close()
	return nil
}

func init() {
	RootCmd.AddCommand(InitCmd)
	RootCmd.AddCommand(AttachCmd)
	RootCmd.AddCommand(DetachCmd)
	RootCmd.AddCommand(WaitAttachCmd)
	RootCmd.AddCommand(IsAttachedCmd)
	RootCmd.AddCommand(MountDevCmd)
	RootCmd.AddCommand(UnmountDevCmd)
	RootCmd.AddCommand(MountCmd)
	RootCmd.AddCommand(UnmountCmd)
	RootCmd.AddCommand(GetVolNameCmd)
}

func main() {
	var err error
	logWrt, err = syslog.New(syslog.LOG_WARNING|syslog.LOG_DAEMON, "udsverFlexVol")
	if err != nil {
		log.Fatal(err)
	}
	defer logWrt.Close()

	if logWrt == nil {
		fmt.Println("am Logwrt is nil")
	}
	if err = RootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
