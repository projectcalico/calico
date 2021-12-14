package template

import (
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

var (
	initialProcessRetryInterval = 250 * time.Millisecond
	maxProcessRetryInterval     = 5 * time.Second
)

type Processor interface {
	Process()
}

func Process(config Config) error {
	// Get the template resources.
	ts, err := getTemplateResources(config)
	if err != nil {
		return err
	}

	// Configure the client with the set of prefixes.
	if err := setClientPrefixes(config, ts); err != nil {
		return err
	}

	var lastErr error
	for _, t := range ts {
		if err := t.process(""); err != nil {
			log.Error(err.Error())
			lastErr = err
		}
	}
	return lastErr
}

// Called to notify the client which prefixes will be monitored.
func setClientPrefixes(config Config, trs []*TemplateResource) error {
	prefixes := []string{}

	// Loop through the full set of template resources and get a complete set of
	// unique prefixes that are being watched.
	pmap := map[string]bool{}
	for _, tr := range trs {
		for _, pk := range tr.ExpandedKeys {
			pmap[pk] = true
		}
	}
	for p := range pmap {
		prefixes = append(prefixes, p)
	}

	// Tell the client the set of prefixes.
	return config.StoreClient.SetPrefixes(prefixes)
}

type watchProcessor struct {
	config   Config
	stopChan chan bool
	doneChan chan bool
	errChan  chan error
	wg       sync.WaitGroup
}

func WatchProcessor(config Config, stopChan, doneChan chan bool, errChan chan error) Processor {
	return &watchProcessor{config, stopChan, doneChan, errChan, sync.WaitGroup{}}
}

func (p *watchProcessor) Process() {
	defer close(p.doneChan)
	// Get the set of template resources.
	ts, err := getTemplateResources(p.config)
	if err != nil {
		log.Fatal(err.Error())
		return
	}

	// Configure the client with the set of prefixes.
	if err := setClientPrefixes(p.config, ts); err != nil {
		log.Fatal(err.Error())
		return
	}

	// Start the individual watchers for each template.
	for _, t := range ts {
		t := t
		p.wg.Add(1)
		go p.monitorPrefix(t)
	}
	p.wg.Wait()
}

func (p *watchProcessor) monitorPrefix(t *TemplateResource) {
	defer p.wg.Done()
	var revision uint64
	for {
		// Watch from the last revision that we updated the templates with.  This will exit it the
		// data in the datastore for the requested prefixes has had updates since that revision.
		key, err := t.storeClient.WatchPrefix(t.Prefix, t.ExpandedKeys, revision, p.stopChan)
		if err != nil {
			p.errChan <- err
			// Prevent backend errors from consuming all resources.
			time.Sleep(time.Second * 2)
			continue
		}

		// Get the current datastore revision and then populate the template with the current settings.
		// The templates will be populated with data that is at least as recent as the datastore
		// revision.
		retryInterval := initialProcessRetryInterval
		for {
			revision = t.storeClient.GetCurrentRevision()
			if err = t.process(key); err == nil {
				break
			}

			// We hit an error processing the template - this means the template will not have been
			// rendered.  This may be because the rendered templates are interconnected and the
			// check function for this template is dependent on the other templates being rendered.
			// Rather than blocking on WatchPrefix, sleep for a short period and retry - we'll start
			// with short retry intervals and increase up to 5s.
			log.Debugf("Will retry processing the template in %s", retryInterval)
			p.errChan <- err
			time.Sleep(retryInterval)
			retryInterval *= 2
			if retryInterval > maxProcessRetryInterval {
				retryInterval = maxProcessRetryInterval
			}
		}
	}
}

func getTemplateResources(config Config) ([]*TemplateResource, error) {
	var lastError error
	templates := make([]*TemplateResource, 0)
	log.Debug("Loading template resources from confdir " + config.ConfDir)
	if !isFileExist(config.ConfDir) {
		log.Warning(fmt.Sprintf("Cannot load template resources: confdir '%s' does not exist", config.ConfDir))
		return nil, nil
	}
	paths, err := recursiveFindFiles(config.ConfigDir, "*toml")
	if err != nil {
		return nil, err
	}

	if len(paths) < 1 {
		log.Warning("Found no templates")
	}

	for _, p := range paths {
		log.Debug(fmt.Sprintf("Found template: %s", p))
		t, err := NewTemplateResource(p, config)
		if err != nil {
			lastError = err
			continue
		}
		templates = append(templates, t)
	}
	return templates, lastError
}
