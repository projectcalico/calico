package binder

import (
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type watcher interface {
	// Returns a channel that sends events whenever workload mounts are created or removed
	watch() <-chan workloadEvent
}

type Operation int

const (
	Added Operation = iota
	Removed
)

const CredentialsSubdir = "creds"
const CredentialsExtension = ".json"
const PollSleepTime = 100 * time.Millisecond

type workloadEvent struct {
	// What happended to the workload mount?
	op  Operation
	uid string
}

func NewWatcher(path string) watcher {
	return &pollWatcher{path}
}

type pollWatcher struct {
	path string
}

func (p *pollWatcher) watch() <-chan workloadEvent {
	c := make(chan workloadEvent)
	go p.poll(c)
	return c
}

func (p *pollWatcher) poll(events chan<- workloadEvent) {
	// The workloads we know about.
	known := make(map[string]bool)
	credPath := filepath.Join(p.path, CredentialsSubdir)
	for {
		if _, err := os.Stat(credPath); err != nil {
			time.Sleep(PollSleepTime)
		} else {
			break
		}
	}
	log.Println("Ready to parse credential directory")
	for {
		// list the contents of the directory
		files, err := ioutil.ReadDir(credPath)
		if err != nil {
			log.Printf("error reading %s: %v", p.path, err)
			close(events)
			return
		}
		// This set will contain all previously known UIDs that are now absent.
		removed := copyStringSet(known)
		for _, file := range files {
			isCred, uid := parseFilename(file.Name())
			if isCred {
				if !known[uid] {
					events <- workloadEvent{op: Added, uid: uid}
					known[uid] = true
				}
				delete(removed, uid)
			}
		}
		// Send updates for UIDs we no longer know about.
		for uid := range removed {
			events <- workloadEvent{op: Removed, uid: uid}
			delete(known, uid)
		}
		time.Sleep(PollSleepTime)
	}
}

func parseFilename(name string) (isCred bool, uid string) {
	if strings.HasSuffix(name, CredentialsExtension) {
		return true, strings.TrimSuffix(name, CredentialsExtension)
	} else {
		return false, ""
	}
}

func copyStringSet(original map[string]bool) map[string]bool {
	n := make(map[string]bool)
	for k, v := range original {
		n[k] = v
	}
	return n
}
