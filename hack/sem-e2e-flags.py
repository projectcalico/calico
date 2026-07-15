#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = ["pyyaml"]
# ///
# Copyright (c) 2026 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Resolve the effective value of an env var — by default K8S_E2E_FLAGS, and
its --ginkgo.focus / --ginkgo.skip — for the jobs in a Semaphore pipeline.

A Semaphore job's env vars are layered, most-specific-wins:

    global_job_config.env_vars  <  block task.env_vars  <  job env_vars  <  matrix

so a job often does not set the var itself but inherits it from its block or
from the pipeline global config. This tool applies that precedence for you, so
you can read a job's real focus/skip without hand-tracing parent scopes.

Usage:
  sem-e2e-flags.py PIPELINE.yml                    # list every job
  sem-e2e-flags.py PIPELINE.yml -b "Block name"    # jobs in one block
  sem-e2e-flags.py PIPELINE.yml -b "Block" -j "Job name"
  sem-e2e-flags.py PIPELINE.yml --var SOME_ENV_VAR # resolve another var
  sem-e2e-flags.py PIPELINE.yml --json             # machine-readable

The pipeline argument is a single Semaphore YAML file (one pipeline per file).
"""

import argparse
import json
import re
import sys

import yaml


def _env_map(env_vars):
    """Turn a Semaphore env_vars list ([{name, value}, ...]) into a dict."""
    out = {}
    for e in env_vars or []:
        if isinstance(e, dict) and "name" in e:
            out[e["name"]] = e.get("value", "")
    return out


def resolve_var(doc, var):
    """Resolve `var` for every job in the pipeline.

    Returns a list of dicts: {block, job, source, value}. A matrixed var
    expands to one entry per matrix value. `source` is the scope the value
    came from: matrix | job | block | global | unset.
    """
    global_env = _env_map((doc.get("global_job_config") or {}).get("env_vars"))
    rows = []
    for block in doc.get("blocks") or []:
        bname = block.get("name", "")
        task = block.get("task") or {}
        block_env = _env_map(task.get("env_vars"))
        for job in task.get("jobs") or []:
            jname = job.get("name", "")
            job_env = _env_map(job.get("env_vars"))
            matrix_values = None
            for m in job.get("matrix") or []:
                if m.get("env_var") == var:
                    matrix_values = m.get("values") or []

            if matrix_values is not None:
                variants = [(v, "matrix") for v in matrix_values]
            elif var in job_env:
                variants = [(job_env[var], "job")]
            elif var in block_env:
                variants = [(block_env[var], "block")]
            elif var in global_env:
                variants = [(global_env[var], "global")]
            else:
                variants = [(None, "unset")]

            for value, source in variants:
                rows.append({"block": bname, "job": jname,
                             "source": source, "value": value})
    return rows


def extract_ginkgo_flags(value):
    """Split a flag string into {ginkgo-flag-name: value}.

    Each flag's value runs until the next ' --ginkgo.' or the end of the
    string, so regexes containing spaces (e.g. `Tiered RBAC`) are preserved
    and flag order does not matter.
    """
    flags = {}
    if not value:
        return flags
    for m in re.finditer(r"--ginkgo\.([A-Za-z0-9._-]+)=", value):
        start = m.end()
        nxt = value.find(" --ginkgo.", start)
        raw = value[start:] if nxt == -1 else value[start:nxt]
        flags[m.group(1)] = raw.strip()
    return flags


def _print_row(row, var):
    flags = extract_ginkgo_flags(row["value"])
    print(f"block: {row['block']}")
    print(f"job:   {row['job']}")
    print(f"  {var} source: {row['source']}")
    if row["value"] is None:
        print("  (not set in this pipeline)")
    else:
        print(f"  focus: {flags.get('focus', '(unset)')}")
        print(f"  skip:  {flags.get('skip', '(none)')}")
        other = {k: v for k, v in flags.items() if k not in ("focus", "skip")}
        for k, v in other.items():
            print(f"  {k}: {v}")
        print(f"  raw:   {row['value']}")
    print()


_DESCRIPTION = """\
Resolve the effective value of an environment variable for the jobs in a
Semaphore pipeline, following Semaphore's env-var precedence:

    global_job_config.env_vars  <  block task.env_vars  <  job env_vars  <  matrix

Jobs frequently do not set a variable themselves but inherit it from their
block or the pipeline's global config. This tool applies that precedence so you
can read a job's real value without tracing parent scopes by hand. By default
it resolves K8S_E2E_FLAGS and splits out --ginkgo.focus / --ginkgo.skip; use
--var to resolve any other variable."""

_EPILOG = """\
examples:
  # List every job in the pipeline with the scope its value comes from
  sem-e2e-flags.py .semaphore/semaphore.yml

  # Show all jobs in one block
  sem-e2e-flags.py .semaphore/end-to-end/pipelines/bpf.yml -b "BPF run matrix"

  # Show one job's resolved focus/skip
  sem-e2e-flags.py .semaphore/end-to-end/pipelines/bpf.yml \\
      -b "BPF run matrix" -j "AWS single subnet, dual IP-family"

  # Resolve a different variable, as JSON
  sem-e2e-flags.py .semaphore/semaphore.yml --var PROVISIONER --json

notes:
  - Quote block/job names; they contain spaces and parentheses.
  - -j requires -b. An unknown -b/-j prints the available names and exits 2.
  - The pipeline argument must be a full, assembled Semaphore pipeline (e.g.
    .semaphore/semaphore.yml or a file under .semaphore/end-to-end/pipelines/).
    Fragments under .semaphore/semaphore.yml.d/blocks/ are partials with no
    global_job_config and will not resolve inherited values."""


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=_DESCRIPTION,
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("pipeline", help="path to a Semaphore pipeline YAML file")
    ap.add_argument("-b", "--block", help="only show jobs in this block (exact name)")
    ap.add_argument("-j", "--job", help="only show this job (exact name); needs --block")
    ap.add_argument("--var", default="K8S_E2E_FLAGS",
                    help="env var to resolve (default: K8S_E2E_FLAGS)")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = ap.parse_args(argv)

    with open(args.pipeline) as f:
        doc = yaml.safe_load(f)

    rows = resolve_var(doc, args.var)

    if args.block is not None:
        blocks = {r["block"] for r in rows}
        if args.block not in blocks:
            print(f"block {args.block!r} not found. Available blocks:", file=sys.stderr)
            for b in sorted(blocks):
                print(f"  {b}", file=sys.stderr)
            return 2
        rows = [r for r in rows if r["block"] == args.block]
    if args.job is not None:
        jobs = {r["job"] for r in rows}
        if args.job not in jobs:
            print(f"job {args.job!r} not found in the selected block(s). Available jobs:",
                  file=sys.stderr)
            for jb in sorted(jobs):
                print(f"  {jb}", file=sys.stderr)
            return 2
        rows = [r for r in rows if r["job"] == args.job]

    if args.json:
        for r in rows:
            r["ginkgo"] = extract_ginkgo_flags(r["value"])
        json.dump(rows, sys.stdout, indent=2)
        print()
        return 0

    if not (args.block or args.job):
        # compact listing of every job
        print(f"{'source':<7} {'block':<34} {'job'}")
        for r in rows:
            print(f"{r['source']:<7} {r['block'][:32]:<34} {r['job']}")
        print(f"\n{len(rows)} job(s). Re-run with -b/-j for a job's full focus/skip.")
        return 0

    for r in rows:
        _print_row(r, args.var)
    return 0


if __name__ == "__main__":
    sys.exit(main())
