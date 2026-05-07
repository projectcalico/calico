// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// certify runs Openshift preflight against Calico images and optionally
// submits the results to Openshift Connect for the certification process.
//
// The certification process also requires:
//   - the operator metadata bundle (see the tigera/operator repo) to be
//     submitted by PR to https://github.com/redhat-openshift-ecosystem/certified-operators
//   - running the Openshift End-to-End tests for CNI and CNV; results are
//     passed to the Certification team for verification.
//
// Neither of those is handled here.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

const catalogAPIBase = "https://catalog.redhat.com/api/containers/v1/projects/certification/id/"

var httpClient = &http.Client{Timeout: 30 * time.Second}

const valuesFilePath = "../../charts/tigera-operator/values.yaml"

var linuxPlatforms = []string{"amd64", "arm64", "s390x", "ppc64le"}

var calicoImageProject = map[string]string{
	"node":                         "5e61a7ab06151b52d45a1148",
	"cni":                          "5e7e3829afa92f4963e7d9db",
	"kube-controllers":             "5e6054f906151b52d45a1081",
	"typha":                        "5e60724f2f3c1acdd05f6012",
	"pod2daemon-flexvol":           "5e6054fb06151b52d45a1082",
	"apiserver":                    "64b7c1758357ec6208cd2c72",
	"csi":                          "64b7c10b46357734e64690ac",
	"node-driver-registrar":        "64c01702093679e0f47fa153",
	"flannel-migration-controller": "5e619bec2c5f183d03415978",
	"dikastes":                     "5e619e432f3c1acdd05f6240",
}

var operatorImageProject = map[string]string{
	"operator": "5e60736f2f3c1acdd05f6014",
}

type checkResult struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Help        string `json:"help,omitempty"`
	Suggestion  string `json:"suggestion,omitempty"`
}

type preflightResults struct {
	Image   string `json:"image"`
	Passed  bool   `json:"passed"`
	Results struct {
		Passed []checkResult `json:"passed"`
		Failed []checkResult `json:"failed"`
		Errors []checkResult `json:"errors"`
	} `json:"results"`
}

type scanJob struct {
	image    string
	platform string
	org      string
	project  string
	version  string
	workdir  string
}

type scanResult struct {
	job       scanJob
	output    []byte
	runErr    error
	preflight *preflightResults
	parseErr  error
}

type rootOpts struct {
	calicoVersion   string
	operatorVersion string
	rhAPIKey        string
	allowMaster     bool
}

func main() {
	defaultCalico, defaultOperator, err := readChartVersions(valuesFilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not read defaults from %s: %v\n", valuesFilePath, err)
	}
	if defaultCalico == "" {
		defaultCalico = "master"
	}
	if defaultOperator == "" {
		defaultOperator = "master"
	}

	if err := newRootCmd(defaultCalico, defaultOperator).Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd(defaultCalico, defaultOperator string) *cobra.Command {
	opts := &rootOpts{}
	cmd := &cobra.Command{
		Use:           "certify",
		Short:         "Openshift preflight runner and certification checker for Calico images",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if opts.allowMaster {
				return nil
			}
			bad := false
			if opts.calicoVersion == "master" {
				fmt.Fprintln(os.Stderr, "WARNING: --calico-version is \"master\" — not a valid certification target.")
				bad = true
			}
			if opts.operatorVersion == "master" {
				fmt.Fprintln(os.Stderr, "WARNING: --operator-version is \"master\" — not a valid certification target.")
				bad = true
			}
			if bad {
				fmt.Fprintln(os.Stderr, "Pass --allow-master to bypass this check.")
				os.Exit(2)
			}
			return nil
		},
	}
	cmd.PersistentFlags().StringVar(&opts.calicoVersion, "calico-version", envOr("CALICO_VERSION", defaultCalico), "calico version to certify")
	cmd.PersistentFlags().StringVar(&opts.operatorVersion, "operator-version", envOr("OPERATOR_VERSION", defaultOperator), "operator version to certify")
	cmd.PersistentFlags().StringVar(&opts.rhAPIKey, "rh-api-key", os.Getenv("RH_API_KEY"), "Red Hat API key (sent as the X-API-KEY header)")
	cmd.PersistentFlags().BoolVar(&opts.allowMaster, "allow-master", false, "proceed even if a version is \"master\" (not a valid certification target)")
	cmd.AddCommand(newRunCmd(opts), newCheckCmd(opts))
	return cmd
}

func newRunCmd(opts *rootOpts) *cobra.Command {
	var (
		preflightTag string
		submit       bool
		concurrency  int
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run preflight scans against Calico images and optionally submit results to Openshift Connect",
		RunE: func(cmd *cobra.Command, args []string) error {
			if submit && opts.rhAPIKey == "" {
				fmt.Fprintln(os.Stderr, "--submit requires --rh-api-key (or RH_API_KEY env var)")
				os.Exit(2)
			}
			if cmd.Flags().Changed("concurrency") && concurrency > 0 {
				runtime.GOMAXPROCS(concurrency)
			}
			return runScans(opts, preflightTag, submit, concurrency)
		},
	}
	cmd.Flags().StringVar(&preflightTag, "preflight-tag", envOr("PREFLIGHT_TAG", "stable"), "preflight image tag")
	cmd.Flags().BoolVar(&submit, "submit", os.Getenv("SUBMIT") == "--submit", "actually submit results to Openshift Connect")
	cmd.Flags().IntVar(&concurrency, "concurrency", runtime.GOMAXPROCS(0), "number of scans to run concurrently; if set, also overrides GOMAXPROCS")
	return cmd
}

func newCheckCmd(opts *rootOpts) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Fetch certification status from catalog.redhat.com and report per-architecture results",
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.rhAPIKey == "" {
				fmt.Fprintln(os.Stderr, "check requires --rh-api-key (or RH_API_KEY env var)")
				os.Exit(2)
			}
			return runCertCheck(opts)
		},
	}
	return cmd
}

func runScans(opts *rootOpts, preflightTag string, submit bool, concurrency int) error {
	outputRoot := "output-" + opts.calicoVersion
	jobs := buildJobs(outputRoot, opts.calicoVersion, opts.operatorVersion)

	if err := os.MkdirAll(outputRoot, 0o755); err != nil {
		return fmt.Errorf("failed to create %s: %w", outputRoot, err)
	}

	preflightImage := "quay.io/opdev/preflight:" + preflightTag
	fmt.Printf("Pulling %s\n", preflightImage)
	if out, err := exec.Command("podman", "pull", preflightImage).CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", out)
		return fmt.Errorf("podman pull: %w", err)
	}

	fmt.Printf("Running %d scans (concurrency %d)\n", len(jobs), concurrency)

	var privileged map[string]bool
	if opts.rhAPIKey != "" {
		fmt.Println("Fetching project info from catalog.redhat.com")
		privileged = fetchProjectPrivileged(jobs, opts.rhAPIKey)
	} else {
		fmt.Fprintln(os.Stderr, "note: no --rh-api-key supplied; skipping project privileged-flag lookup")
	}

	results := runJobs(jobs, concurrency, preflightImage, opts.rhAPIKey, submit)

	if err := consolidate(outputRoot, linuxPlatforms); err != nil {
		fmt.Fprintf(os.Stderr, "consolidation failed: %v\n", err)
	}

	if !printReport(results, privileged) {
		os.Exit(1)
	}
	return nil
}

func runCertCheck(opts *rootOpts) error {
	outputRoot := "output-" + opts.calicoVersion
	jobs := buildJobs(outputRoot, opts.calicoVersion, opts.operatorVersion)
	fmt.Println("Fetching certification status from catalog.redhat.com")
	certResults := fetchAllCertStatus(jobs, opts.rhAPIKey)
	if !printCertStatus(certResults) {
		os.Exit(1)
	}
	return nil
}

type projectInfo struct {
	Container struct {
		Privileged bool `json:"privileged"`
	} `json:"container"`
}

func fetchProjectInfo(projectID, apiKey string) (*projectInfo, error) {
	req, err := http.NewRequest(http.MethodGet, catalogAPIBase+projectID, nil)
	if err != nil {
		return nil, err
	}

	req.Header["X-API-KEY"] = []string{apiKey}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var pi projectInfo
	if err := json.NewDecoder(resp.Body).Decode(&pi); err != nil {
		return nil, err
	}
	return &pi, nil
}

type imageCertEntry struct {
	Architecture string `json:"architecture"`
	Certified    bool   `json:"certified"`
	Repositories []struct {
		Tags []struct {
			Name string `json:"name"`
		} `json:"tags"`
	} `json:"repositories"`
}

type imagesResponse struct {
	Data     []imageCertEntry `json:"data"`
	Page     int              `json:"page"`
	PageSize int              `json:"page_size"`
	Total    int              `json:"total"`
}

func fetchProjectImagesPaged(projectID, apiKey string) ([]imageCertEntry, error) {
	var all []imageCertEntry
	url := fmt.Sprintf("https://catalog.redhat.com/api/containers/v1/projects/certification/id/%s/images", projectID)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header["X-API-KEY"] = []string{apiKey}
	req.Header["Accept"] = []string{"application/json"}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var ir imagesResponse
	err = json.NewDecoder(resp.Body).Decode(&ir)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	all = append(all, ir.Data...)
	if len(ir.Data) == 0 || len(all) >= ir.Total {
		return all, nil
	}
	return all, nil
}

type certStatus int

const (
	certMissing certStatus = iota
	certNotCertified
	certCertified
)

type imageCertResult struct {
	image    string
	version  string
	statuses map[string]certStatus // arch -> status
	err      error
}

func entryHasVersion(e imageCertEntry, version string) bool {
	for _, repo := range e.Repositories {
		for _, tag := range repo.Tags {
			if tag.Name == version {
				return true
			}
		}
	}
	return false
}

// checkProjectCertification fetches all images for a project and classifies
// each architecture in linuxPlatforms as certified, not certified (arch
// present but no entry satisfies all criteria), or missing (no entry at all
// for that arch).
func checkProjectCertification(projectID, version, apiKey string) (map[string]certStatus, error) {
	entries, err := fetchProjectImagesPaged(projectID, apiKey)
	if err != nil {
		return nil, err
	}
	archPresent := map[string]bool{}
	archCertified := map[string]bool{}
	for _, e := range entries {
		archPresent[e.Architecture] = true
		if e.Certified && entryHasVersion(e, version) {
			archCertified[e.Architecture] = true
		}
	}
	statuses := map[string]certStatus{}
	for _, arch := range linuxPlatforms {
		switch {
		case archCertified[arch]:
			statuses[arch] = certCertified
		case archPresent[arch]:
			statuses[arch] = certNotCertified
		default:
			statuses[arch] = certMissing
		}
	}
	return statuses, nil
}

// fetchAllCertStatus runs checkProjectCertification concurrently for every
// unique image in jobs.
func fetchAllCertStatus(jobs []scanJob, apiKey string) []imageCertResult {
	type info struct{ projectID, version string }
	seen := map[string]info{}
	for _, j := range jobs {
		seen[j.image] = info{j.project, j.version}
	}
	results := make([]imageCertResult, 0, len(seen))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for image, i := range seen {
		wg.Add(1)
		go func(image string, i info) {
			defer wg.Done()
			statuses, err := checkProjectCertification(i.projectID, i.version, apiKey)
			mu.Lock()
			results = append(results, imageCertResult{
				image:    image,
				version:  i.version,
				statuses: statuses,
				err:      err,
			})
			mu.Unlock()
		}(image, i)
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].image < results[j].image })
	return results
}

// printCertStatus prints the per-image certification breakdown and returns
// true if every image is fully certified across all linuxPlatforms.
func printCertStatus(results []imageCertResult) bool {
	fmt.Println()
	fmt.Println("================ certification status ================")
	allOK := true
	for _, r := range results {
		fmt.Printf("\n%s @ %s:\n", r.image, r.version)
		if r.err != nil {
			fmt.Printf("  error: %v\n", r.err)
			allOK = false
			continue
		}
		var certified, notCertified, missing []string
		for _, arch := range linuxPlatforms {
			switch r.statuses[arch] {
			case certCertified:
				certified = append(certified, arch)
			case certNotCertified:
				notCertified = append(notCertified, arch)
			case certMissing:
				missing = append(missing, arch)
			}
		}
		if len(certified) > 0 {
			fmt.Printf("  certified:     %s\n", strings.Join(certified, ", "))
		}
		if len(notCertified) > 0 {
			fmt.Printf("  not certified: %s\n", strings.Join(notCertified, ", "))
			allOK = false
		}
		if len(missing) > 0 {
			fmt.Printf("  missing:       %s\n", strings.Join(missing, ", "))
			allOK = false
		}
	}
	return allOK
}

// fetchProjectPrivileged returns image -> privileged for every unique project
// referenced by jobs. Failures are reported as warnings and the corresponding
// image is omitted (treated as not privileged).
func fetchProjectPrivileged(jobs []scanJob, apiKey string) map[string]bool {
	seen := map[string]string{}
	for _, j := range jobs {
		seen[j.image] = j.project
	}
	privileged := make(map[string]bool, len(seen))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for image, projectID := range seen {
		wg.Add(1)
		go func(image, projectID string) {
			defer wg.Done()
			pi, err := fetchProjectInfo(projectID, apiKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: project info for %s (%s): %v\n", image, projectID, err)
				return
			}
			mu.Lock()
			privileged[image] = pi.Container.Privileged
			mu.Unlock()
		}(image, projectID)
	}
	wg.Wait()
	return privileged
}

func buildJobs(outputRoot, calicoVersion, operatorVersion string) []scanJob {
	var jobs []scanJob
	add := func(images map[string]string, org, version string) {
		for _, image := range sortedKeys(images) {
			for _, platform := range linuxPlatforms {
				jobs = append(jobs, scanJob{
					image:    image,
					platform: platform,
					org:      org,
					project:  images[image],
					version:  version,
					workdir:  filepath.Join(outputRoot, image, platform),
				})
			}
		}
	}
	add(calicoImageProject, "quay.io/calico", calicoVersion)
	add(operatorImageProject, "quay.io/tigera", operatorVersion)
	return jobs
}

func runJobs(jobs []scanJob, concurrency int, preflightImage, apiKey string, submit bool) []scanResult {
	if concurrency < 1 {
		concurrency = 1
	}
	results := make([]scanResult, len(jobs))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, job := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, job scanJob) {
			defer wg.Done()
			defer func() { <-sem }()
			fmt.Printf("[start] %s/%s\n", job.image, job.platform)
			results[i] = runScan(job, preflightImage, apiKey, submit)
			fmt.Printf("[done ] %s/%s — %s\n", job.image, job.platform, summarise(results[i]))
		}(i, job)
	}
	wg.Wait()
	return results
}

func runScan(job scanJob, preflightImage, apiKey string, submit bool) scanResult {
	res := scanResult{job: job}
	if err := os.MkdirAll(job.workdir, 0o755); err != nil {
		res.runErr = fmt.Errorf("mkdir %s: %w", job.workdir, err)
		return res
	}
	abs, err := filepath.Abs(job.workdir)
	if err != nil {
		res.runErr = fmt.Errorf("abs %s: %w", job.workdir, err)
		return res
	}

	imageRef := fmt.Sprintf("%s/%s:%s", job.org, job.image, job.version)
	args := []string{
		"run", "--rm", "--security-opt=label=disable",
		"--env", "PFLT_PLATFORM=" + job.platform,
		"--env", "PFLT_ARTIFACTS=/artifacts",
		"--env", "PFLT_LOGFILE=/artifacts/preflight.log",
		"--env", "PFLT_CERTIFICATION_COMPONENT_ID=" + job.project,
		"--env", "PFLT_PYXIS_API_TOKEN=" + apiKey,
		"-v", abs + ":/artifacts",
		preflightImage,
		"check", "container", imageRef,
	}
	if submit {
		args = append(args, "--submit")
	}

	var buf bytes.Buffer
	cmd := exec.Command("podman", args...)
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		res.runErr = err
	}
	res.output = buf.Bytes()

	data, err := os.ReadFile(filepath.Join(job.workdir, "results.json"))
	if err != nil {
		res.parseErr = fmt.Errorf("read results.json: %w", err)
		return res
	}
	var pr preflightResults
	if err := json.Unmarshal(data, &pr); err != nil {
		res.parseErr = fmt.Errorf("parse results.json: %w", err)
		return res
	}
	res.preflight = &pr
	return res
}

func summarise(r scanResult) string {
	switch {
	case r.runErr != nil:
		return fmt.Sprintf("podman error: %v", r.runErr)
	case r.parseErr != nil:
		return fmt.Sprintf("parse error: %v", r.parseErr)
	case r.preflight == nil:
		return "no results"
	case r.preflight.Passed:
		return "passed"
	default:
		return fmt.Sprintf("did not pass (%d failed, %d errors)",
			len(r.preflight.Results.Failed), len(r.preflight.Results.Errors))
	}
}

func consolidate(outputRoot string, platforms []string) error {
	for _, platform := range platforms {
		matches, err := filepath.Glob(filepath.Join(outputRoot, "*", platform, "results.json"))
		if err != nil {
			return err
		}
		out := filepath.Join(outputRoot, platform+"-results.json")
		f, err := os.Create(out)
		if err != nil {
			return err
		}
		for _, m := range matches {
			data, err := os.ReadFile(m)
			if err != nil {
				f.Close()
				return err
			}
			if _, err := f.Write(data); err != nil {
				f.Close()
				return err
			}
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	return nil
}

// printReport writes the end-of-run summary and returns true if every scan
// passed cleanly. Errors are consolidated per image: each unique error lists
// the architectures it affects, with help and suggestion shown once.
//
// privileged is image -> whether the corresponding Openshift Connect project
// has .container.privileged=true; for those images, RunAsNonRoot failures
// (but not errors) are hidden from the output.
func printReport(results []scanResult, privileged map[string]bool) bool {
	var podmanFails, scanIssues []scanResult
	for _, r := range results {
		switch {
		case r.runErr != nil, r.preflight == nil:
			podmanFails = append(podmanFails, r)
		case scanHasRemainingIssues(r, privileged):
			scanIssues = append(scanIssues, r)
		}
	}

	fmt.Println()
	fmt.Println("===================== summary =====================")
	fmt.Printf("scans run: %d, podman failures: %d, scans with issues: %d\n",
		len(results), len(podmanFails), len(scanIssues))

	if len(podmanFails) > 0 {
		printPodmanFails(podmanFails)
	}
	if len(scanIssues) > 0 {
		printScanIssues(scanIssues, privileged)
	}

	if len(podmanFails) == 0 && len(scanIssues) == 0 {
		fmt.Println("All scans passed.")
		return true
	}
	return false
}

// failureHidden reports whether a failed check should be suppressed for the
// given image. RunAsNonRoot is expected to fail on projects whose Openshift
// Connect entry is marked privileged.
func failureHidden(c checkResult, image string, privileged map[string]bool) bool {
	return c.Name == "RunAsNonRoot" && privileged[image]
}

func scanHasRemainingIssues(r scanResult, privileged map[string]bool) bool {
	if r.preflight == nil {
		return false
	}
	if len(r.preflight.Results.Errors) > 0 {
		return true
	}
	for _, c := range r.preflight.Results.Failed {
		if !failureHidden(c, r.job.image, privileged) {
			return true
		}
	}
	return false
}

// archIndex returns a comparator that orders architectures by their position
// in linuxPlatforms (unknown ones sort last).
func archIndex(a string) int {
	for i, p := range linuxPlatforms {
		if p == a {
			return i
		}
	}
	return len(linuxPlatforms)
}

func sortArchs(archs []string) {
	sort.Slice(archs, func(i, j int) bool { return archIndex(archs[i]) < archIndex(archs[j]) })
}

func printPodmanFails(fails []scanResult) {
	fmt.Println()
	fmt.Println("--- podman runs that failed ---")

	type key struct{ msg, output string }
	byImage := map[string]map[key][]string{}
	for _, r := range fails {
		m := byImage[r.job.image]
		if m == nil {
			m = map[key][]string{}
			byImage[r.job.image] = m
		}
		k := key{summarise(r), string(r.output)}
		m[k] = append(m[k], r.job.platform)
	}

	images := make([]string, 0, len(byImage))
	for i := range byImage {
		images = append(images, i)
	}
	sort.Strings(images)

	for _, image := range images {
		m := byImage[image]
		fmt.Printf("\n%s:\n", image)
		keys := make([]key, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i].msg < keys[j].msg })
		for _, k := range keys {
			archs := m[k]
			sortArchs(archs)
			fmt.Printf("  %s [%s]\n", k.msg, strings.Join(archs, ", "))
			if k.output != "" {
				for line := range strings.SplitSeq(strings.TrimRight(k.output, "\n"), "\n") {
					fmt.Printf("    %s\n", line)
				}
			}
		}
	}
}

func printScanIssues(issues []scanResult, privileged map[string]bool) {
	fmt.Println()
	fmt.Println("--- preflight failures and errors ---")

	type key struct{ kind, name string }
	type val struct {
		help, suggestion string
		archs            []string
	}
	byImage := map[string]map[key]*val{}
	record := func(image, platform, kind string, c checkResult) {
		m := byImage[image]
		if m == nil {
			m = map[key]*val{}
			byImage[image] = m
		}
		k := key{kind, c.Name}
		v := m[k]
		if v == nil {
			v = &val{help: c.Help, suggestion: c.Suggestion}
			m[k] = v
		}
		v.archs = append(v.archs, platform)
	}
	for _, r := range issues {
		for _, c := range r.preflight.Results.Failed {
			if failureHidden(c, r.job.image, privileged) {
				continue
			}
			record(r.job.image, r.job.platform, "FAIL", c)
		}
		for _, c := range r.preflight.Results.Errors {
			record(r.job.image, r.job.platform, "ERROR", c)
		}
	}

	images := make([]string, 0, len(byImage))
	for i := range byImage {
		images = append(images, i)
	}
	sort.Strings(images)

	for _, image := range images {
		m := byImage[image]
		keys := make([]key, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i].kind != keys[j].kind {
				return keys[i].kind == "FAIL" // FAIL before ERROR
			}
			return keys[i].name < keys[j].name
		})

		fmt.Printf("\n%s:\n", image)
		for _, k := range keys {
			v := m[k]
			sortArchs(v.archs)
			fmt.Printf("  %-5s %s [%s]\n", k.kind, k.name, strings.Join(v.archs, ", "))
			if v.help != "" {
				fmt.Printf("        help: %s\n", v.help)
			}
			if v.suggestion != "" {
				fmt.Printf("        suggestion: %s\n", v.suggestion)
			}
		}
	}
}

// readChartVersions extracts the Calico (calicoctl.tag) and operator
// (tigeraOperator.version) versions from the helm values.yaml. The format is
// stable and shallow enough that a small line scanner avoids pulling in a YAML
// dep.
func readChartVersions(path string) (calico, operator string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	section := ""
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if !(line[0] == ' ' || line[0] == '\t') {
			if i := strings.IndexByte(line, ':'); i > 0 {
				section = line[:i]
			} else {
				section = ""
			}
			continue
		}
		key, val, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		switch {
		case section == "tigeraOperator" && key == "version":
			operator = val
		case section == "calicoctl" && key == "tag":
			calico = val
		}
	}
	if err := s.Err(); err != nil {
		return "", "", err
	}
	return calico, operator, nil
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
