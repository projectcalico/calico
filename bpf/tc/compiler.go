// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

// Copyright (c) 2020  All rights reserved.

package tc

import (
	"bufio"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/bpf"
	"github.com/projectcalico/felix/idalloc"
	"github.com/projectcalico/felix/proto"
)

// TCHook is the hook to which a BPF program should be attached.  This is relative to the host namespace
// so workload PolDirnIngress policy is attached to the HookEgress.
type Hook string

const (
	HookIngress Hook = "ingress"
	HookEgress  Hook = "egress"
)

const (
	CompileFlagHostEp  = 1
	CompileFlagIngress = 2
	CompileFlagTunnel  = 4
	CompileFlagCgroup  = 8
)

type ToOrFromEp string

const (
	FromEp ToOrFromEp = "from"
	ToEp   ToOrFromEp = "to"
)

type EndpointType string

const (
	EpTypeWorkload EndpointType = "workload"
	EpTypeHost     EndpointType = "host"
	EpTypeTunnel   EndpointType = "tunnel"
)

func SectionName(endpointType EndpointType, fromOrTo ToOrFromEp) string {
	return fmt.Sprintf("calico_%s_%s_ep", fromOrTo, endpointType)
}

var sectionToFlags = map[string]int{}

func init() {
	sectionToFlags[SectionName(EpTypeWorkload, FromEp)] = 0
	sectionToFlags[SectionName(EpTypeWorkload, ToEp)] = CompileFlagIngress
	sectionToFlags[SectionName(EpTypeHost, FromEp)] = CompileFlagHostEp | CompileFlagIngress
	sectionToFlags[SectionName(EpTypeHost, ToEp)] = CompileFlagHostEp
	sectionToFlags[SectionName(EpTypeTunnel, FromEp)] = CompileFlagHostEp | CompileFlagIngress | CompileFlagTunnel
	sectionToFlags[SectionName(EpTypeTunnel, ToEp)] = CompileFlagHostEp | CompileFlagTunnel
}

func SectionToFlags(section string) int {
	flags, ok := sectionToFlags[section]
	if !ok {
		logrus.WithField("section", section).Panic("Unknown BPF section")
	}
	return flags
}

// CompileTCOption specifies additional compile options for TC programs
type CompileOption func(*compileOpts)

type compileOpts struct {
	extraArgs []string
	dir       string
	srcFile   string
	outFile   string
	bpftool   bool
}

func (o *compileOpts) appendExtraArg(a string) {
	o.extraArgs = append(o.extraArgs, a)
}

// CompileWithEndpointToHostDrop sets whether workload-to-host traffic is dropped.
func CompileWithEndpointToHostDrop(drop bool) CompileOption {
	return func(opts *compileOpts) {
		opts.appendExtraArg(fmt.Sprintf("-DCALI_DROP_WORKLOAD_TO_HOST=%v", drop))
	}
}

// CompileWithDefine makes a -Dname defined
func CompileWithDefine(name string) CompileOption {
	return func(opts *compileOpts) {
		opts.appendExtraArg(fmt.Sprintf("-D%s", name))
	}
}

// CompileWithDefineValue makes a -Dname=value defined
func CompileWithDefineValue(name string, value string) CompileOption {
	return func(opts *compileOpts) {
		opts.appendExtraArg(fmt.Sprintf("-D%s=%s", name, value))
	}
}

// CompileWithEntrypointName controls the name of the BPF section entrypoint.
func CompileWithEntrypointName(name string) CompileOption {
	return CompileWithDefineValue("CALI_ENTRYPOINT_NAME", name)
}

// CompileWithIncludePath adds an include path to search for includes
func CompileWithIncludePath(p string) CompileOption {
	return func(opts *compileOpts) {
		opts.appendExtraArg(fmt.Sprintf("-I%s", p))
	}
}

// CompileWithFIBEnabled sets whether FIB lookup is allowed
func CompileWithFIBEnabled(enabled bool) CompileOption {
	return func(opts *compileOpts) {
		opts.appendExtraArg(fmt.Sprintf("-DCALI_FIB_LOOKUP_ENABLED=%v", enabled))
	}
}

// CompileWithLogLevel sets the log level of the resulting program
func CompileWithLogLevel(level string) CompileOption {
	return func(opts *compileOpts) {
		opts.appendExtraArg(fmt.Sprintf("-DCALI_LOG_LEVEL=CALI_LOG_LEVEL_%s", level))
	}
}

// CompileWithLogPrefix sets a specific log prefix for the resulting program
func CompileWithLogPrefix(prefix string) CompileOption {
	return func(opts *compileOpts) {
		opts.appendExtraArg(fmt.Sprintf("-DCALI_LOG_PFX=%v", prefix))
	}
}

// CompileWithSourceName sets the source file name
func CompileWithSourceName(f string) CompileOption {
	return func(opts *compileOpts) {
		opts.srcFile = f
	}
}

// CompileWithOutputName sets the output name
func CompileWithOutputName(f string) CompileOption {
	return func(opts *compileOpts) {
		opts.outFile = f
	}
}

// CompileWithWorkingDir sets the working directory
func CompileWithWorkingDir(dir string) CompileOption {
	return func(opts *compileOpts) {
		opts.dir = dir
	}
}

// CompileWithBpftoolLoader makes the result loadable by bpftool (in contrast to
// iproute2 only)
func CompileWithBpftoolLoader() CompileOption {
	return func(opts *compileOpts) {
		opts.bpftool = true
	}
}

// CompileWithHostIP makes the host ip available for the bpf code
func CompileWithHostIP(ip net.IP) CompileOption {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return CompileWithDefineValue("CALI_HOST_IP", "bad-host-ip")
	}
	return CompileWithDefineValue("CALI_HOST_IP",
		fmt.Sprintf("0x%02x%02x%02x%02x", ipv4[3], ipv4[2], ipv4[1], ipv4[0]))
}

// CompileWithVxlanPort sets the VXLAN port to use to override the IANA default
func CompileWithVxlanPort(port uint16) CompileOption {
	return CompileWithDefineValue("CALI_VXLAN_PORT", fmt.Sprintf("%d", port))
}

// CompileWithNATTunnelMTU sets the MTU for NAT tunnel
func CompileWithNATTunnelMTU(mtu uint16) CompileOption {
	return CompileWithDefineValue("CALI_NAT_TUNNEL_MTU", fmt.Sprintf("%d", mtu))
}

// CompileWithFlags sets the CALI_COMPILE_FLAGS value.
func CompileWithFlags(flags int) CompileOption {
	return CompileWithDefineValue("CALI_COMPILE_FLAGS", fmt.Sprint(flags))
}

// CompileProgramToFile takes policy rules and compiles them into a tc-bpf
// program and saves it into the provided file. Extra CFLAGS can be provided
func CompileProgramToFile(allRules [][][]*proto.Rule, ipSetIDAlloc *idalloc.IDAllocator, opts ...CompileOption) error {
	compileOpts := compileOpts{
		srcFile: "/code/bpf/tc/templates/tc_template.c",
		outFile: "/tmp/tc.o",
		dir:     "/code/bpf/tc",
	}

	for _, o := range opts {
		o(&compileOpts)
	}

	args := []string{
		"-x",
		"c",
		"-D__KERNEL__",
		"-D__ASM_SYSREG_H",
	}

	if compileOpts.bpftool {
		args = append(args, "-D__BPFTOOL_LOADER__")
	}

	args = append(args, compileOpts.extraArgs...)

	args = append(args, []string{
		"-I" + compileOpts.dir,
		"-Wno-unused-value",
		"-Wno-pointer-sign",
		"-Wno-compare-distinct-pointer-types",
		"-Wunused",
		"-Wall",
		"-Werror",
		"-fno-stack-protector",
		"-O2",
		"-emit-llvm",
		"-c", "-", "-o", "-",
	}...)
	logrus.WithField("args", args).Debug("About to run clang")
	clang := exec.Command("clang", args...)
	clang.Dir = compileOpts.dir
	clangStdin, err := clang.StdinPipe()
	if err != nil {
		return err
	}
	clangStdout, err := clang.StdoutPipe()
	if err != nil {
		return err
	}
	clangStderr, err := clang.StderrPipe()
	if err != nil {
		return err
	}

	logrus.WithField("command", clang.String()).Infof("compiling bpf")

	err = clang.Start()
	if err != nil {
		logrus.WithError(err).Panic("Failed to write C file.")
		return err
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(clangStderr)
		for scanner.Scan() {
			logrus.Warnf("clang stderr: %s", scanner.Text())
		}
		if err != nil {
			logrus.WithError(err).Error("Error while reading clang stderr")
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		pg, err := bpf.NewProgramGenerator(compileOpts.srcFile, ipSetIDAlloc)
		if err != nil {
			logrus.WithError(err).Panic("Failed to create code generator")
		}
		err = pg.WriteProgram(clangStdin, allRules)
		if err != nil {
			logrus.WithError(err).Panic("Failed to write C file.")
		}
		err = clangStdin.Close()
		if err != nil {
			logrus.WithError(err).Panic("Failed to write C file to clang stdin (Close() failed).")
		}
	}()
	llc := exec.Command("llc", "-march=bpf", "-filetype=obj", "-o", compileOpts.outFile)
	llc.Stdin = clangStdout
	out, err := llc.CombinedOutput()
	if err != nil {
		logrus.WithError(err).WithField("out", string(out)).Error("Failed to compile C program (llc step)")
		return err
	}
	err = clang.Wait()
	if err != nil {
		logrus.WithError(err).Error("Clang failed.")
		return err
	}
	wg.Wait()

	return nil
}

func ProgFilename(epType EndpointType, toOrFrom ToOrFromEp, epToHostDrop bool, fibEnabled bool, logLevel string) string {
	var hostDropPart string
	if epType == EpTypeWorkload && epToHostDrop {
		hostDropPart = "host_drop_"
	}
	fibPart := ""
	if fibEnabled {
		fibPart = "fib_"
	}
	logLevel = strings.ToLower(logLevel)
	if logLevel == "off" {
		logLevel = "no_log"
	}
	var epTypeShort string
	switch epType {
	case EpTypeWorkload:
		epTypeShort = "wep"
	case EpTypeHost:
		epTypeShort = "hep"
	case EpTypeTunnel:
		epTypeShort = "tnl"
	}
	oFileName := fmt.Sprintf("%v_%v_%s%s%v.o", toOrFrom, epTypeShort, hostDropPart, fibPart, logLevel)
	return oFileName
}
