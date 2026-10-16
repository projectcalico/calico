package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/containerd/platforms"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/projectcalico/calico/toolchain/internal/archutil"
)

var (
	mount       string
	toInstall   string
	toUninstall string
	flVersion   bool
)

func init() {
	flag.StringVar(&mount, "mount", "/proc/sys/fs/binfmt_misc", "binfmt_misc mount point")
	flag.StringVar(&toInstall, "install", "", "architectures to install")
	flag.StringVar(&toUninstall, "uninstall", "", "architectures to uninstall")
	flag.BoolVar(&flVersion, "version", false, "display version")

	// completely discard cache for archutil.SupportedPlatforms
	archutil.CacheMaxAge = 0
}

func uninstall(arch string) error {
	fis, err := os.ReadDir(mount)
	if err != nil {
		return err
	}
	for _, fi := range fis {
		if fi.Name() == "register" || fi.Name() == "status" || fi.Name() == "WSLInterop" {
			continue
		}
		if fi.Name() == arch || strings.HasSuffix(fi.Name(), "-"+arch) {
			return os.WriteFile(filepath.Join(mount, fi.Name()), []byte("-1"), 0600)
		}
	}
	return errors.Errorf("not found")
}

func getBinaryNames(cfg config) (string, string, error) {
	binaryPath := "/usr/bin"
	if v := os.Getenv("QEMU_BINARY_PATH"); v != "" {
		binaryPath = v
	}
	binaryBasename := cfg.binary
	if binaryPrefix := os.Getenv("QEMU_BINARY_PREFIX"); binaryPrefix != "" {
		if strings.ContainsRune(binaryPrefix, os.PathSeparator) {
			return "", "", errors.New("binary prefix must not contain path separator (Hint: set $QEMU_BINARY_PATH to specify the directory)")
		}
		binaryBasename = binaryPrefix + binaryBasename
	}
	binaryFullpath := filepath.Join(binaryPath, binaryBasename)
	return binaryBasename, binaryFullpath, nil
}

func install(arch string) error {
	cfg, ok := configs[arch]
	if !ok {
		return errors.Errorf("unsupported architecture: %v", arch)
	}
	register := filepath.Join(mount, "register")
	file, err := os.OpenFile(register, os.O_WRONLY, 0)
	if err != nil {
		var pathErr *os.PathError
		ok := errors.As(err, &pathErr)
		if ok && errors.Is(pathErr.Err, syscall.ENOENT) {
			return errors.Errorf("ENOENT opening %s is it mounted?", register)
		}
		if ok && errors.Is(pathErr.Err, syscall.EPERM) {
			return errors.Errorf("EPERM opening %s check permissions?", register)
		}
		return errors.Errorf("Cannot open %s: %s", register, err)
	}
	defer file.Close()

	flags := "CF"
	if v := os.Getenv("QEMU_PRESERVE_ARGV0"); v != "" {
		flags += "P"
	}
	binaryBasename, binaryFullpath, err := getBinaryNames(cfg)
	if err != nil {
		return err
	}

	line := fmt.Sprintf(":%s:M:0:%s:%s:%s:%s", binaryBasename, cfg.magic, cfg.mask, binaryFullpath, flags)

	// short writes should not occur on sysfs, cannot usefully recover
	_, err = file.Write([]byte(line))
	if err != nil {
		var pathErr *os.PathError
		if errors.As(err, &pathErr) && errors.Is(pathErr.Err, syscall.EEXIST) {
			return errors.Errorf("%s already registered", binaryBasename)
		}
		return errors.Errorf("cannot register %q to %s: %s", binaryFullpath, register, err)
	}
	return nil
}

func printStatus() error {
	fis, err := os.ReadDir(mount)
	if err != nil {
		return err
	}
	var emulators []string
	for _, f := range fis {
		if f.Name() == "register" || f.Name() == "status" {
			continue
		}
		dt, err := os.ReadFile(filepath.Join(mount, f.Name()))
		if err != nil {
			return err
		}
		if strings.HasPrefix(string(dt), "enabled") {
			emulators = append(emulators, f.Name())
		}
	}

	out := struct {
		Supported []string `json:"supported"`
		Emulators []string `json:"emulators"`
	}{
		Supported: formatPlatforms(archutil.SupportedPlatforms(true)),
		Emulators: emulators,
	}

	dt, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", dt)
	return nil
}

func formatPlatforms(p []ocispecs.Platform) []string {
	str := make([]string, 0, len(p))
	for _, pp := range p {
		str = append(str, platforms.FormatAll(platforms.Normalize(pp)))
	}
	return str
}

func parseArch(in string) (out []string) {
	if in == "" {
		return
	}
	for _, v := range strings.Split(in, ",") {
		p, err := platforms.Parse(v)
		if err != nil {
			out = append(out, v)
		} else {
			out = append(out, p.Architecture)
		}
	}
	return
}

func parseUninstall(in string) (out []string) {
	if in == "" {
		return
	}
	for _, v := range strings.Split(in, ",") {
		if p, err := platforms.Parse(v); err == nil {
			if c, ok := configs[p.Architecture]; ok {
				v = strings.TrimPrefix(c.binary, "qemu-")
			}
		}
		fis, err := filepath.Glob(filepath.Join(mount, v))
		if err != nil || len(fis) == 0 {
			out = append(out, v)
		}
		for _, fi := range fis {
			out = append(out, filepath.Base(fi))
		}
	}
	return
}

func main() {
	log.SetFlags(0) // no timestamps in logs
	flag.Parse()
	if err := run(); err != nil {
		log.Printf("error: %+v", err)
	}
}

func run() error {
	if flVersion {
		log.Printf("binfmt/%s qemu/%s go/%s", revision, qemuVersion, runtime.Version()[2:])
		return nil
	}

	if _, err := os.Stat(filepath.Join(mount, "status")); err != nil {
		if err := syscall.Mount("binfmt_misc", mount, "binfmt_misc", 0, ""); err != nil {
			return errors.Wrapf(err, "cannot mount binfmt_misc filesystem at %s", mount)
		}
		defer syscall.Unmount(mount, 0)
	}

	for _, name := range parseUninstall(toUninstall) {
		err := uninstall(name)
		if err == nil {
			log.Printf("uninstalling: %s OK", name)
		} else {
			log.Printf("uninstalling: %s %v", name, err)
		}
	}

	var installArchs []string
	if toInstall == "all" {
		installArchs = allArch()
	} else {
		installArchs = parseArch(toInstall)
	}

	// best effort workaround for kernels that do not immediately expose new
	// binfmt_misc entries after register writes until the mountpoint is touched:
	// https://github.com/amazonlinux/amazon-linux-2023/issues/479#issuecomment-2707623971
	if len(installArchs) > 0 {
		now := time.Now()
		_ = os.Chtimes(mount, now, now)
	}

	for _, name := range installArchs {
		err := install(name)
		if err == nil {
			log.Printf("installing: %s OK", name)
		} else {
			log.Printf("installing: %s %v", name, err)
		}
	}

	return printStatus()
}
