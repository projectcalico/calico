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
its --ginkgo.focus / --ginkgo.skip — for the steps in an ArgoCI "condensed"
e2e cron (.argoci/cron/e2e-*.yaml).

This is the Argo counterpart of sem-e2e-flags.py. An Argo step's env vars are
layered, most-specific-wins:

    globalPrologue default  <  step env  <  matrix variant env

The globalPrologue default is the shell fallback `export VAR="${VAR:-...}"`,
used only when a step (or matrix variant) does not set the var itself. Many
steps set no flags of their own and inherit that default, so this tool applies
the precedence for you rather than making you read one `value:` line and hope.

Usage:
  argo-e2e-flags.py CRON.yaml                     # list every step
  argo-e2e-flags.py CRON.yaml -j "step-name"      # one step's focus/skip
  argo-e2e-flags.py CRON.yaml --var SOME_ENV_VAR  # resolve another var
  argo-e2e-flags.py CRON.yaml --json              # machine-readable

The argument is a single condensed ArgoCI cron YAML (one workflow per file).
Argo steps are flat (no Semaphore-style block), so there is no -b flag; a step
name is the whole `<block>-<job>` identifier, e.g. bpf-run-matrix-aws-encap.
"""

import argparse
import json
import re
import sys

import yaml


def _env_map(env_list):
    """Turn an Argo env list ([{name, value}, ...]) into a dict."""
    out = {}
    for e in env_list or []:
        if isinstance(e, dict) and "name" in e:
            out[e["name"]] = e.get("value", "")
    return out


def _spec_default(doc, var):
    """Extract the globalPrologue shell default for `var`, i.e. the value in
    `export VAR="${VAR:-<value>}"`. Returns None if there is no such default."""
    prologue = doc.get("globalPrologue") or ""
    pattern = re.escape(var) + r'="\$\{' + re.escape(var) + r':-(.*)\}"'
    m = re.search(pattern, prologue)
    return m.group(1) if m else None


def resolve_var(doc, var):
    """Resolve `var` for every step in the cron.

    Returns a list of dicts: {step, variant, source, value}. When a matrix
    variant sets the var, it expands to one entry per variant. `source` is the
    scope the value came from: matrix | step | default | unset.
    """
    default = _spec_default(doc, var)
    rows = []
    for step in doc.get("steps") or []:
        sname = step.get("name", "")
        step_env = _env_map(step.get("env"))
        matrix = step.get("matrix") or []
        var_in_matrix = any(var in _env_map(v.get("env")) for v in matrix)

        if var_in_matrix:
            for v in matrix:
                venv = _env_map(v.get("env"))
                if var in venv:
                    value, source = venv[var], "matrix"
                elif var in step_env:
                    value, source = step_env[var], "step"
                elif default is not None:
                    value, source = default, "default"
                else:
                    value, source = None, "unset"
                rows.append({"step": sname, "variant": v.get("name", ""),
                             "source": source, "value": value})
        else:
            if var in step_env:
                value, source = step_env[var], "step"
            elif default is not None:
                value, source = default, "default"
            else:
                value, source = None, "unset"
            rows.append({"step": sname, "variant": None,
                         "source": source, "value": value})
    return rows


def extract_ginkgo_flags(value):
    """Split a flag string into {ginkgo-flag-name: value}.

    Each flag's value runs until the next ' --ginkgo.' or the end of the
    string, so regexes containing spaces (e.g. `Tiered RBAC`) are preserved,
    flag order does not matter, and skip-only or focus-only strings are handled.
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
    print(f"step: {row['step']}")
    if row["variant"] is not None:
        print(f"  variant: {row['variant']}")
    print(f"  {var} source: {row['source']}")
    if row["value"] is None:
        print("  (not set — no step env and no globalPrologue default)")
    else:
        # An empty --ginkgo.focus (or none at all) means Ginkgo selects ALL
        # specs, so surface that explicitly rather than printing "(unset)".
        focus = flags.get("focus")
        print(f"  focus: {focus if focus else '(none — selects ALL specs)'}")
        print(f"  skip:  {flags.get('skip', '(none)')}")
        other = {k: v for k, v in flags.items() if k not in ("focus", "skip")}
        for k, v in other.items():
            print(f"  {k}: {v}")
        print(f"  raw:   {row['value']}")
    print()


_DESCRIPTION = """\
Resolve the effective value of an environment variable for the steps in an
ArgoCI "condensed" e2e cron, following the env-var precedence:

    globalPrologue default  <  step env  <  matrix variant env

Many steps set no flags of their own and inherit the globalPrologue shell
default (`export VAR="${VAR:-...}"`), so reading one step's `value:` line is not
enough. This tool applies the precedence and, by default, splits K8S_E2E_FLAGS
into its --ginkgo.focus / --ginkgo.skip; use --var to resolve another variable.

This is the Argo counterpart of hack/sem-e2e-flags.py."""

_EPILOG = """\
examples:
  # List every step in the cron with the scope its value comes from
  argo-e2e-flags.py .argoci/cron/e2e-bpf.yaml

  # Show one step's resolved focus/skip
  argo-e2e-flags.py .argoci/cron/e2e-bpf.yaml -j 9k-mtu-runs-aws-bpf-9k-mtu

  # Resolve a different variable, as JSON
  argo-e2e-flags.py .argoci/cron/e2e-iptables.yaml --var PROVISIONER --json

notes:
  - A step whose K8S_E2E_FLAGS has no --ginkgo.focus selects ALL specs (Ginkgo
    only filters by --ginkgo.skip then), which is easy to miss by eye.
  - source=default means the step inherits the globalPrologue fallback.
  - The argument must be a condensed ArgoCI cron (.argoci/cron/e2e-*.yaml), not
    the expanded CronWorkflow the handler generates."""


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=_DESCRIPTION,
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("cron", help="path to a condensed ArgoCI cron YAML file")
    ap.add_argument("-j", "--job", "--step", dest="step",
                    help="only show this step (exact name)")
    ap.add_argument("--var", default="K8S_E2E_FLAGS",
                    help="env var to resolve (default: K8S_E2E_FLAGS)")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = ap.parse_args(argv)

    with open(args.cron) as f:
        doc = yaml.safe_load(f)
    if not isinstance(doc, dict) or "steps" not in doc:
        print(f"{args.cron}: not a condensed ArgoCI cron (no top-level 'steps').",
              file=sys.stderr)
        return 2

    rows = resolve_var(doc, args.var)

    if args.step is not None:
        names = {r["step"] for r in rows}
        if args.step not in names:
            print(f"step {args.step!r} not found. Available steps:", file=sys.stderr)
            for s in sorted(names):
                print(f"  {s}", file=sys.stderr)
            return 2
        rows = [r for r in rows if r["step"] == args.step]

    if args.json:
        for r in rows:
            r["ginkgo"] = extract_ginkgo_flags(r["value"])
        json.dump(rows, sys.stdout, indent=2)
        print()
        return 0

    if args.step is None:
        print(f"{'source':<8} {'step'}")
        for r in rows:
            variant = f"  [{r['variant']}]" if r["variant"] is not None else ""
            print(f"{r['source']:<8} {r['step']}{variant}")
        print(f"\n{len(rows)} step/variant row(s). Re-run with -j for a step's full focus/skip.")
        return 0

    for r in rows:
        _print_row(r, args.var)
    return 0


if __name__ == "__main__":
    sys.exit(main())
