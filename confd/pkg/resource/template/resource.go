package template

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"text/template"

	"github.com/BurntSushi/toml"
	"github.com/kelseyhightower/memkv"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/confd/pkg/backends"
)

type Config struct {
	ConfDir       string
	ConfigDir     string
	KeepStageFile bool
	Noop          bool
	Prefix        string
	StoreClient   backends.StoreClient
	SyncOnly      bool
	TemplateDir   string
}

// TemplateResourceConfig holds the parsed template resource.
type TemplateResourceConfig struct {
	TemplateResource TemplateResource `toml:"template"`
}

// TemplateResource is the representation of a parsed template resource.
type TemplateResource struct {
	CheckCmd      string `toml:"check_cmd"`
	Dest          string
	FileMode      os.FileMode
	Gid           int
	Keys          []string
	Mode          string
	Prefix        string
	ReloadCmd     string `toml:"reload_cmd"`
	Src           string
	StageFile     *os.File
	Uid           int
	ExpandedKeys  []string
	funcMap       map[string]interface{}
	keepStageFile bool
	noop          bool
	store         memkv.Store
	storeClient   backends.StoreClient
	syncOnly      bool
	shellCmd      string
}

var ErrEmptySrc = errors.New("empty src template")

// NewTemplateResource creates a TemplateResource.
func NewTemplateResource(path string, config Config) (*TemplateResource, error) {
	if config.StoreClient == nil {
		return nil, errors.New("A valid StoreClient is required.")
	}

	// Set the default uid and gid so we can determine if it was
	// unset from configuration.
	tc := &TemplateResourceConfig{TemplateResource{Uid: -1, Gid: -1}}

	log.Debug("Loading template resource from " + path)
	_, err := toml.DecodeFile(path, &tc)
	if err != nil {
		return nil, fmt.Errorf("Cannot process template resource %s - %s", path, err.Error())
	}

	tr := &tc.TemplateResource
	tr.keepStageFile = config.KeepStageFile
	tr.noop = config.Noop
	tr.storeClient = config.StoreClient
	tr.funcMap = newFuncMap()
	tr.store = memkv.New()
	tr.syncOnly = config.SyncOnly
	addFuncs(tr.funcMap, tr.store.FuncMap)

	if runtime.GOOS == "windows" {
		tr.shellCmd = "powershell"
	} else {
		tr.shellCmd = "/bin/sh"
	}

	if config.Prefix != "" {
		tr.Prefix = config.Prefix
	}

	if !strings.HasPrefix(tr.Prefix, "/") {
		tr.Prefix = "/" + tr.Prefix
	}

	// Replace "NODENAME" in the prefix by the actual node name.
	tr.Prefix = strings.Replace(tr.Prefix, "//NODENAME", "/"+NodeName, 1)

	if tr.Src == "" {
		return nil, ErrEmptySrc
	}

	if tr.Uid == -1 {
		tr.Uid = os.Geteuid()
	}

	if tr.Gid == -1 {
		tr.Gid = os.Getegid()
	}

	// Calculate the set of keys including the prefix.
	tr.ExpandedKeys = expandKeys(tr.Prefix, tr.Keys)

	tr.Src = filepath.Join(config.TemplateDir, tr.Src)
	return tr, nil
}

// setVars sets the Vars for template resource.
func (t *TemplateResource) setVars() error {
	var err error
	log.Debug("Retrieving keys from store")
	log.Debug("Key prefix set to " + t.Prefix)

	result, err := t.storeClient.GetValues(t.ExpandedKeys)
	if err != nil {
		return err
	}

	t.store.Purge()

	for k, v := range result {
		t.store.Set(path.Join("/", strings.TrimPrefix(k, t.Prefix)), v)
	}
	return nil
}

// createStageFile stages the src configuration file by processing the src
// template and setting the desired owner, group, and mode. It also sets the
// StageFile for the template resource.
// It returns an error if any.
func (t *TemplateResource) createStageFile() error {
	log.Debug("Using source template " + t.Src)

	if !isFileExist(t.Src) {
		return errors.New("Missing template: " + t.Src)
	}

	log.Debug("Compiling source template " + t.Src)

	tmpl, err := template.New(filepath.Base(t.Src)).Funcs(t.funcMap).ParseFiles(t.Src)
	if err != nil {
		return fmt.Errorf("Unable to process template %s, %s", t.Src, err)
	}

	// create TempFile in Dest directory to avoid cross-filesystem issues
	temp, err := os.CreateTemp(filepath.Dir(t.Dest), "."+filepath.Base(t.Dest))
	if err != nil {
		return err
	}

	if err = tmpl.Execute(temp, nil); err != nil {
		// The key error to return is the failure to execute.
		// to preserve that error ignore the errors in close and clean
		temp.Close()           // nolint:errcheck
		os.Remove(temp.Name()) // nolint:errcheck
		return err
	}
	defer func() {
		if e := temp.Close(); e != nil {
			// Just log the error but don't carry it up the calling stack.
			log.WithError(e).WithField("filename", temp.Name()).Error("error closing file")
		}
	}()

	// Set the owner, group, and mode on the stage file now to make it easier to
	// compare against the destination configuration file later.
	if err := os.Chmod(temp.Name(), t.FileMode); err != nil {
		log.WithError(err).WithField("filename", temp.Name()).Error("error changing mode")
		return err
	}

	if runtime.GOOS != "windows" {
		// Windows doesn't support chown, apparently:
		// resource.go 178: error changing ownership error=chown .peerings.ps1761844858: not supported by windows filename=".peerings.ps1761844858"
		if err := os.Chown(temp.Name(), t.Uid, t.Gid); err != nil {
			log.WithError(err).WithField("filename", temp.Name()).Error("error changing ownership")
			return err
		}
	}
	t.StageFile = temp
	return nil
}

// sync compares the staged and dest config files and attempts to sync them
// if they differ. sync will run a config check command if set before
// overwriting the target config file. Finally, sync will run a reload command
// if set to have the application or service pick up the changes.
// It returns an error if any.
func (t *TemplateResource) sync(key string) error {
	staged := t.StageFile.Name()
	if t.keepStageFile {
		log.Info("Keeping staged file: " + staged)
	} else {
		defer func() {
			if e := os.Remove(staged); e != nil {
				if !os.IsNotExist(e) {
					// Just log the error but don't carry it up the calling stack.
					log.WithError(e).WithField("filename", staged).Error("error removing file")
				} else {
					log.Debugf("Ignore not exists err. %s", e.Error())
				}
			}
		}()
	}

	log.Debug("Comparing candidate config to " + t.Dest)
	ok, err := sameConfig(staged, t.Dest)
	if err != nil {
		log.Error(err.Error())
	}
	if t.noop {
		log.Warning("Noop mode enabled. " + t.Dest + " will not be modified")
		return nil
	}
	if !ok {
		log.Debug("Target config " + t.Dest + " out of sync")
		if !t.syncOnly && t.CheckCmd != "" {
			if err := t.check(); err != nil {
				if isFileExist(t.Dest) {
					return errors.New("Config check failed: " + err.Error())
				}
				log.Info("Check failed, but file does not yet exist - create anyway")
			}
		}
		log.Debug("Overwriting target config " + t.Dest)
		err := os.Rename(staged, t.Dest)
		if err != nil {
			if strings.Contains(err.Error(), "device or resource busy") {
				log.Debug("Rename failed - target is likely a mount. Trying to write instead")
				// try to open the file and write to it
				var contents []byte
				var rerr error
				contents, rerr = os.ReadFile(staged)
				if rerr != nil {
					return rerr
				}
				if err := os.WriteFile(t.Dest, contents, t.FileMode); err != nil {
					log.WithError(err).WithField("filename", t.Dest).Error("failed to write to file")
					return err
				}
				// make sure owner and group match the temp file, in case the file was created with WriteFile
				if err := os.Chown(t.Dest, t.Uid, t.Gid); err != nil {
					log.WithError(err).WithField("filename", t.Dest).Error("failed to change owner")
					return err
				}

			} else {
				return err
			}
		}
		if !t.syncOnly && t.ReloadCmd != "" {
			if err := t.reload(); err != nil {
				return err
			}
		}
		msg := "Target config " + t.Dest + " has been updated"
		if key != "" {
			msg += fmt.Sprintf(" due to change in key: %s", key)
		}
		log.Info(msg)
	} else {
		log.Debug("Target config " + t.Dest + " in sync")
	}
	return nil
}

// check executes the check command to validate the staged config file. The
// command is modified so that any references to src template are substituted
// with a string representing the full path of the staged file. This allows the
// check to be run on the staged file before overwriting the destination config
// file.
// It returns nil if the check command returns 0 and there are no other errors.
func (t *TemplateResource) check() error {
	var cmdBuffer bytes.Buffer
	data := make(map[string]string)
	data["src"] = t.StageFile.Name()
	tmpl, err := template.New("checkcmd").Parse(t.CheckCmd)
	if err != nil {
		return err
	}
	if err := tmpl.Execute(&cmdBuffer, data); err != nil {
		return err
	}
	log.Debug("Running checkcmd: " + cmdBuffer.String())
	c := exec.Command(t.shellCmd, "-c", cmdBuffer.String())
	output, err := c.CombinedOutput()
	if err != nil {
		log.Errorf("Error from checkcmd %q: %q", cmdBuffer.String(), string(output))
		return err
	}
	log.Debug(fmt.Sprintf("Output from checkcmd: %q", string(output)))
	return nil
}

// reload executes the reload command.
// It returns nil if the reload command returns 0.
func (t *TemplateResource) reload() error {
	log.Debug("Running reloadcmd: " + t.ReloadCmd)
	c := exec.Command(t.shellCmd, "-c", t.ReloadCmd)
	output, err := c.CombinedOutput()
	if err != nil {
		log.Error(fmt.Sprintf("Error from reloadcmd: %q", string(output)))
		return err
	}
	log.Debug(fmt.Sprintf("Output from reloadcmd: %q", string(output)))
	return nil
}

// process is a convenience function that wraps calls to the three main tasks
// required to keep local configuration files in sync. First we gather vars
// from the store, then we stage a candidate configuration file, and finally sync
// things up.
// It accepts an optional string representing the key that triggered this processing.
// It returns an error if any.
func (t *TemplateResource) process(key string) error {
	if err := t.setFileMode(); err != nil {
		return err
	}
	if err := t.setVars(); err != nil {
		return err
	}
	if err := t.createStageFile(); err != nil {
		return err
	}
	if err := t.sync(key); err != nil {
		return err
	}
	return nil
}

// setFileMode sets the FileMode.
func (t *TemplateResource) setFileMode() error {
	if t.Mode == "" {
		if !isFileExist(t.Dest) {
			t.FileMode = 0644
		} else {
			fi, err := os.Stat(t.Dest)
			if err != nil {
				return err
			}
			t.FileMode = fi.Mode()
		}
	} else {
		mode, err := strconv.ParseUint(t.Mode, 0, 32)
		if err != nil {
			return err
		}
		t.FileMode = os.FileMode(mode)
	}
	return nil
}
