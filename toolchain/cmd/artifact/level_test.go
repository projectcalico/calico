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

package main

import (
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

const step = "run1/step1/"

func TestHelp(t *testing.T) {
	for _, args := range [][]string{nil, {"help"}, {"-h"}, {"--help"}} {
		h := newHarness(t)
		h.mustRun(0, args...)
		h.wantStdout(usage)
	}
}

func TestUnknownCommand(t *testing.T) {
	h := newHarness(t)
	h.mustRun(1, "bogus")
	h.wantStderr("[ERROR] artifact: unknown command 'bogus'\n" + usage)
}

func TestArgumentErrors(t *testing.T) {
	for _, tc := range []struct {
		args  []string
		unset string
		want  string
	}{
		{args: []string{"push"}, want: "push: missing storage level (expected 'job' or 'workflow')"},
		{args: []string{"pull", "project"}, want: "pull: unknown storage level 'project' (expected 'job' or 'workflow')"},
		{args: []string{"push", "job", "x"}, unset: "CI_ARTIFACT_STEP_STORAGE", want: "CI_ARTIFACT_STEP_STORAGE is not set"},
		{args: []string{"list", "workflow"}, unset: "CI_ARTIFACT_STORAGE", want: "CI_ARTIFACT_STORAGE is not set"},
		{args: []string{"push", "job", "x", "--bogus"}, want: "unknown option '--bogus'"},
		{args: []string{"push", "job", "x", "--destination"}, want: "option '--destination' needs a value"},
		{args: []string{"push", "job", "x", "--labels", "novalue"}, want: "--labels entry 'novalue' must be key=value"},
		{args: []string{"pull", "job", "x", "--labels=a=b,=c"}, want: "--labels entry '=c' must be key=value"},
		{args: []string{"push", "job"}, want: "push: need a file or directory to upload"},
		{args: []string{"pull", "job"}, want: "pull: need a remote path to download"},
		{args: []string{"yank", "job"}, want: "yank: need a remote path to download and delete"},
		{args: []string{"push", "job", "missing"}, want: "push: 'missing' does not exist"},
	} {
		h := newHarness(t)
		if tc.unset != "" {
			delete(h.env, tc.unset)
		}
		h.mustRun(1, tc.args...)
		h.wantStderr("[ERROR] artifact: " + tc.want + "\n")
	}
}

func TestStorageMustBeGCS(t *testing.T) {
	h := newHarness(t)
	h.env["CI_ARTIFACT_STEP_STORAGE"] = "/tmp/artifacts"
	h.mustRun(1, "list", "job")
	h.wantStderr("CI_ARTIFACT_STEP_STORAGE: '/tmp/artifacts' is not a gs:// location")
}

func TestPushSingleFile(t *testing.T) {
	h := newHarness(t)
	writeFile(t, "out/report.html", "<html/>")
	mtime := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := os.Chtimes("out/report.html", mtime, mtime); err != nil {
		t.Fatal(err)
	}
	h.mustRun(0, "push", "job", "./out/report.html")
	o := h.bucket("art").get(t, step+"report.html")
	if string(o.data) != "<html/>" {
		t.Errorf("data %q", o.data)
	}
	if !strings.HasPrefix(o.contentType, "text/html") {
		t.Errorf("content type %q", o.contentType)
	}
	if got := o.metadata[mtimeKey]; got != strconv.FormatInt(mtime.Unix(), 10) {
		t.Errorf("mtime metadata %q", got)
	}
}

func TestPushWorkflowLevelTrimsOneSlash(t *testing.T) {
	h := newHarness(t)
	writeFile(t, "app", "bin")
	h.mustRun(0, "push", "workflow", "app", "--destination", "bin/app")
	h.bucket("art").get(t, "run1/workflow/bin/app")
}

func TestPushDestination(t *testing.T) {
	for _, tc := range []struct {
		name     string
		existing []string
		args     []string
		want     string
	}{
		{name: "rename", args: []string{"--destination", "sub/renamed.txt"}, want: "sub/renamed.txt"},
		{name: "equals form", args: []string{"--destination=renamed.txt"}, want: "renamed.txt"},
		{name: "short flag", args: []string{"-d", "renamed.txt"}, want: "renamed.txt"},
		{name: "trailing slash is a folder", args: []string{"--destination", "dir/"}, want: "dir/file.txt"},
		{name: "existing remote folder", existing: []string{"dir/other"}, args: []string{"--destination", "dir"}, want: "dir/file.txt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			for _, e := range tc.existing {
				h.bucket("art").put(step+e, nil, "", nil)
			}
			writeFile(t, "file.txt", "x")
			h.mustRun(0, append([]string{"push", "job", "file.txt"}, tc.args...)...)
			h.bucket("art").get(t, step+tc.want)
		})
	}
}

func TestPushForce(t *testing.T) {
	h := newHarness(t)
	h.bucket("art").put(step+"file.txt", []byte("old"), "", nil)
	writeFile(t, "file.txt", "new")

	h.mustRun(1, "push", "job", "file.txt")
	h.wantStderr("[ERROR] artifact: push: 'file.txt' already exists at this level (use --force to overwrite)\n")
	if got := string(h.bucket("art").get(t, step+"file.txt").data); got != "old" {
		t.Fatalf("overwritten without --force: %q", got)
	}

	h.mustRun(0, "push", "job", "file.txt", "--force")
	if got := string(h.bucket("art").get(t, step+"file.txt").data); got != "new" {
		t.Fatalf("not overwritten with --force: %q", got)
	}
}

func TestPushDirectory(t *testing.T) {
	h := newHarness(t)
	writeFile(t, "report/index.html", "i")
	writeFile(t, "report/.hidden", "h")
	writeFile(t, "report/a/b/deep.txt", "d")
	writeFile(t, "elsewhere/target.txt", "t")
	if err := os.Symlink("../elsewhere/target.txt", "report/filelink"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../elsewhere", "report/dirlink"); err != nil {
		t.Fatal(err)
	}
	// rsync never deletes, so objects the directory lacks survive.
	h.bucket("art").put(step+"results/stale.txt", []byte("s"), "", nil)

	h.mustRun(0, "push", "job", "report/", "--destination", "results", "--labels", "stage=e2e,team=core,url=a=b")

	want := []string{
		step + "results/.hidden",
		step + "results/a/b/deep.txt",
		step + "results/filelink",
		step + "results/index.html",
		step + "results/stale.txt",
	}
	if got := h.bucket("art").names(); !slices.Equal(got, want) {
		t.Fatalf("objects %v, want %v", got, want)
	}
	if got := string(h.bucket("art").get(t, step+"results/filelink").data); got != "t" {
		t.Errorf("symlinked file uploaded as %q, want its target's content", got)
	}
	for _, name := range want[:4] {
		md := h.bucket("art").get(t, name).metadata
		if md["stage"] != "e2e" || md["team"] != "core" || md["url"] != "a=b" || md[mtimeKey] == "" {
			t.Errorf("%s metadata %v", name, md)
		}
	}

	// Only an object named exactly like the directory blocks a second push.
	h.mustRun(0, "push", "job", "report", "--destination", "results")
}

func TestPushDirectoryBrokenSymlink(t *testing.T) {
	h := newHarness(t)
	writeFile(t, "report/ok.txt", "ok")
	if err := os.Symlink("missing", "report/broken"); err != nil {
		t.Fatal(err)
	}
	h.mustRun(1, "push", "job", "report")
	if got := h.bucket("art").names(); len(got) != 0 {
		t.Fatalf("uploaded %v despite the broken symlink", got)
	}
}

func TestPushDirectoryOntoObject(t *testing.T) {
	h := newHarness(t)
	h.bucket("art").put(step+"report", nil, "", nil)
	writeFile(t, "report/x", "x")
	h.mustRun(1, "push", "job", "report", "--force")
	h.wantStderr("is an object at this level")
}

func TestPushMultipleSources(t *testing.T) {
	h := newHarness(t)
	writeFile(t, "t/cargo-timing-1.html", "1")
	writeFile(t, "t/cargo-timing-2.html", "2")
	writeFile(t, "logs/x.log", "x")

	h.mustRun(0, "push", "job", "t/cargo-timing-1.html", "t/cargo-timing-2.html", "logs/", "--destination", "timings/")
	h.mustRun(0, "push", "workflow", "t/cargo-timing-1.html", "t/cargo-timing-2.html")

	want := []string{
		step + "timings/cargo-timing-1.html",
		step + "timings/cargo-timing-2.html",
		step + "timings/logs/x.log",
		"run1/workflow/cargo-timing-1.html",
		"run1/workflow/cargo-timing-2.html",
	}
	if got := h.bucket("art").names(); !slices.Equal(got, want) {
		t.Fatalf("objects %v, want %v", got, want)
	}
}

func TestPushMultipleSourcesStopsAtExisting(t *testing.T) {
	h := newHarness(t)
	h.bucket("art").put(step+"b", nil, "", nil)
	writeFile(t, "a", "a")
	writeFile(t, "b", "b")
	writeFile(t, "c", "c")
	h.mustRun(1, "push", "job", "a", "b", "c")
	h.wantStderr("push: 'b' already exists at this level")
	if got := h.bucket("art").names(); !slices.Equal(got, []string{step + "a", step + "b"}) {
		t.Fatalf("objects %v", got)
	}
}

func TestPullFile(t *testing.T) {
	h := newHarness(t)
	mtime := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	h.bucket("art").put(step+"bin/app", []byte("binary"), "", map[string]string{mtimeKey: strconv.FormatInt(mtime.Unix(), 10)})

	h.mustRun(0, "pull", "job", "bin/app")
	if got := readFile(t, "app"); got != "binary" {
		t.Fatalf("content %q", got)
	}
	fi, err := os.Stat("app")
	if err != nil {
		t.Fatal(err)
	}
	if !fi.ModTime().Equal(mtime) {
		t.Errorf("mtime %v, want %v", fi.ModTime(), mtime)
	}
	if want := os.FileMode(0o666) &^ currentUmask(); fi.Mode().Perm() != want {
		t.Errorf("mode %v, want %v", fi.Mode().Perm(), want)
	}

	h.mustRun(1, "pull", "job", "bin/app")
	h.wantStderr("[ERROR] artifact: pull: 'app' already exists locally (use --force to overwrite)\n")

	h.bucket("art").put(step+"bin/app", []byte("newer"), "", nil)
	h.mustRun(0, "pull", "job", "bin/app", "--force")
	if got := readFile(t, "app"); got != "newer" {
		t.Fatalf("content after --force %q", got)
	}

	h.mustRun(0, "pull", "job", "bin/app", "--destination", "nested/dir/app2")
	if got := readFile(t, "nested/dir/app2"); got != "newer" {
		t.Fatalf("content %q", got)
	}

	// Like cp, a destination that is a directory receives the file inside it.
	h.mustRun(0, "pull", "job", "bin/app", "--destination", "nested", "--force")
	if got := readFile(t, "nested/app"); got != "newer" {
		t.Fatalf("content %q", got)
	}
}

func TestPullDirectory(t *testing.T) {
	h := newHarness(t)
	b := h.bucket("art")
	mtime := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	b.put(step+"logs/", nil, "", nil)
	b.put(step+"logs/a.log", []byte("a"), "", map[string]string{mtimeKey: strconv.FormatInt(mtime.Unix(), 10)})
	b.put(step+"logs/sub/b.log", []byte("b"), "", nil)
	b.put(step+"logsx/other", []byte("o"), "", nil)
	created := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	b.objects[step+"logs/sub/b.log"].created = created

	h.mustRun(0, "pull", "job", "logs", "--destination", "out")
	if got := readFile(t, "out/a.log"); got != "a" {
		t.Errorf("a.log %q", got)
	}
	if got := readFile(t, "out/sub/b.log"); got != "b" {
		t.Errorf("b.log %q", got)
	}
	if _, err := os.Stat("out/other"); err == nil {
		t.Errorf("pulled an object from a sibling prefix")
	}
	if fi, _ := os.Stat("out/a.log"); !fi.ModTime().Equal(mtime) {
		t.Errorf("a.log mtime %v, want %v", fi.ModTime(), mtime)
	}
	// Without recorded mtime, rsync used the creation time.
	if fi, _ := os.Stat("out/sub/b.log"); !fi.ModTime().Equal(created) {
		t.Errorf("b.log mtime %v, want %v", fi.ModTime(), created)
	}
}

func TestPullMissing(t *testing.T) {
	h := newHarness(t)
	h.mustRun(1, "pull", "job", "nothing")
	h.wantStderr("pull: 'nothing' does not exist at this level")
	if _, err := os.Stat("nothing"); err == nil {
		t.Errorf("left a local directory behind")
	}
}

func TestYank(t *testing.T) {
	h := newHarness(t)
	b := h.bucket("art")
	b.put(step+"report.txt", []byte("r"), "", nil)
	b.put(step+"dir/x", []byte("x"), "", nil)
	b.put(step+"dir/y/z", []byte("z"), "", nil)
	b.put(step+"dirx/keep", []byte("k"), "", nil)

	h.mustRun(0, "yank", "job", "report.txt")
	h.mustRun(0, "yank", "job", "dir")
	if got := readFile(t, "report.txt") + readFile(t, "dir/x") + readFile(t, "dir/y/z"); got != "rxz" {
		t.Fatalf("downloaded %q", got)
	}
	if got := b.names(); !slices.Equal(got, []string{step + "dirx/keep"}) {
		t.Fatalf("objects left %v", got)
	}
}

func TestYankKeepsRemoteWhenDownloadFails(t *testing.T) {
	h := newHarness(t)
	h.bucket("art").put(step+"report.txt", []byte("r"), "", nil)
	writeFile(t, "report.txt", "local")
	h.mustRun(1, "yank", "job", "report.txt")
	h.wantStderr("yank: 'report.txt' already exists locally")
	h.bucket("art").get(t, step+"report.txt")
}

func TestList(t *testing.T) {
	h := newHarness(t)
	b := h.bucket("art")
	for _, n := range []string{"a.txt", "d/b.txt", "d/e/c.txt", "z.txt", "only/deeper/x"} {
		b.put(step+n, nil, "", nil)
	}
	b.put("run1/step10/not-mine", nil, "", nil)
	const u = "gs://art/" + step

	h.mustRun(0, "list", "job")
	h.wantStdout(u + ":\n" +
		u + "a.txt\n" +
		u + "z.txt\n" +
		"\n" + u + "d/:\n" +
		u + "d/b.txt\n" +
		"\n" + u + "d/e/:\n" +
		u + "d/e/c.txt\n" +
		"\n" + u + "only/:\n" +
		"\n" + u + "only/deeper/:\n" +
		u + "only/deeper/x\n")

	h.mustRun(0, "list", "job", "d")
	h.wantStdout(u + "d/:\n" +
		u + "d/b.txt\n" +
		"\n" + u + "d/e/:\n" +
		u + "d/e/c.txt\n")

	h.mustRun(0, "list", "job", "d/b.txt")
	h.wantStdout(u + "d/b.txt\n")

	h.mustRun(1, "list", "job", "nothing")
	h.wantStderr("list: 'gs://art/run1/step1/nothing' matched no objects")

	h.mustRun(1, "list", "workflow")
	h.wantStderr("matched no objects")
}

func TestStorageOpenedOnlyWhenNeeded(t *testing.T) {
	h := newHarness(t)
	h.mustRun(1, "push", "job")
	h.mustRun(1, "cache", "store", "-k")
	if h.opened != 0 {
		t.Fatalf("storage opened %d times for argument errors", h.opened)
	}
}

func TestBasename(t *testing.T) {
	for in, want := range map[string]string{"": "", "/": "/", "a": "a", "a/b": "b", "a/b/": "b", "./report/": "report", ".": "."} {
		if got := basename(in); got != want {
			t.Errorf("basename(%q) = %q, want %q", in, got, want)
		}
	}
}
