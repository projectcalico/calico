// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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

package xdp

type AttachPoint struct {
	Iface string
}

func (ap *AttachPoint) IfaceName() string {
	return ap.Iface
}

func (ap *AttachPoint) JumpMapFDMapKey() string {
	return "xdp"
}

func (ap *AttachPoint) IsAttached() (bool, error) {
	return false, nil
}

func (ap *AttachPoint) AttachProgram() error {
	//func (b *BPFLib) LoadXDPAuto(ifName string, mode XDPMode) error {
	//	return b.LoadXDP(xdpFilename, ifName, mode)
	//}

	//func (b *BPFLib) LoadXDP(objPath, ifName string, mode XDPMode) error {
	//	mapArgs, err := b.getMapArgs(ifName)
	//	if err != nil {
	//		return err
	//	}
	//
	//	return b.loadXDPRaw(objPath, ifName, mode, mapArgs)
	//}

	//func (b *BPFLib) loadXDPRaw(objPath, ifName string, mode XDPMode, mapArgs []string) error {
	//	objPath = path.Join(b.binDir, objPath)
	//
	//	if _, err := os.Stat(objPath); os.IsNotExist(err) {
	//		return fmt.Errorf("cannot find XDP object %q", objPath)
	//	}
	//
	//	progName := getProgName(ifName)
	//	progPath := filepath.Join(b.xdpDir, progName)
	//
	//	if err := b.loadBPF(objPath, progPath, "xdp", mapArgs); err != nil {
	//		return err
	//	}
	//
	//	prog := "ip"
	//	args := []string{
	//		"link",
	//		"set",
	//		"dev",
	//		ifName,
	//		mode.String(),
	//		"pinned",
	//		progPath}
	//
	//	printCommand(prog, args...)
	//	output, err := exec.Command(prog, args...).CombinedOutput()
	//	log.Debugf("out:\n%v", string(output))
	//
	//	if err != nil {
	//		if removeErr := os.Remove(progPath); removeErr != nil {
	//			return fmt.Errorf("failed to attach XDP program (%s) to %s: %s (also failed to remove the pinned program: %s)\n%s", progPath, ifName, err, removeErr, output)
	//		} else {
	//			return fmt.Errorf("failed to attach XDP program (%s) to %s: %s\n%s", progPath, ifName, err, output)
	//		}
	//	}
	//
	//	return nil
	//}

	return nil
}

func (ap *AttachPoint) ProgramID() (string, error) {
	return "", nil
}
