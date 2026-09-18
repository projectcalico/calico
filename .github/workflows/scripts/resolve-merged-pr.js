// Re-derive the merged PR from a workflow_run head SHA. Stage 2 of a
// workflow_run-driven pick has no PR payload, so it looks the PR up by the
// trigger's head SHA (GitHub-set, trusted) and confirms it merged into the
// expected base branch. Writes step outputs proceed/pr/sha/login to
// $GITHUB_OUTPUT. Reusable by every workflow_run-driven pick/backport flow.
//
// Env:
//   SOURCE_REPO       owner/name the PR lives in.
//   HEAD_SHA          github.event.workflow_run.head_sha.
//   BASE_REF          required base branch (default "master").
//   GH_TOKEN          token for `gh` (set by the caller).
//   RESOLVE_RETRY_MS  retry delay for search-index lag (default 5000).
//   GITHUB_OUTPUT     set by Actions; falls back to stdout for local runs.

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');

const env = process.env;
const SOURCE_REPO = env.SOURCE_REPO || '';
const HEAD_SHA = env.HEAD_SHA || '';
const BASE_REF = env.BASE_REF || 'master';
const RETRY_MS = Number(env.RESOLVE_RETRY_MS ?? 5000);

function gh(args) {
  return execFileSync('gh', args, { encoding: 'utf8' });
}

function sleepSync(ms) {
  if (ms > 0) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function setOutputs(obj) {
  const lines = Object.entries(obj).map(([k, v]) => `${k}=${v}`).join('\n') + '\n';
  if (env.GITHUB_OUTPUT) fs.appendFileSync(env.GITHUB_OUTPUT, lines);
  else process.stdout.write(lines);
}

function skip(msg) {
  console.log(`::notice::${msg} -- skipping`);
  setOutputs({ proceed: false });
}

// Fork PRs aren't returned by the commits->pulls endpoint, so use the search
// API. `sha:` matches every PR that contains the commit, so return ALL
// candidate numbers (not just the first) and let the caller pick the PR whose
// head SHA actually equals HEAD_SHA. Returns an array of numbers (empty on miss).
function findPrs() {
  try {
    const out = gh([
      'api',
      `search/issues?q=sha:${HEAD_SHA}+repo:${SOURCE_REPO}+is:pr`,
      '--jq', '.items[].number',
    ]).trim();
    return out ? out.split('\n').map((n) => n.trim()).filter(Boolean) : [];
  } catch {
    return [];
  }
}

function main() {
  if (!SOURCE_REPO || !HEAD_SHA) {
    skip('SOURCE_REPO or HEAD_SHA unset');
    return;
  }

  let nums = findPrs();
  if (!nums.length) {
    // The search index can lag a few seconds behind a fresh merge; retry once.
    sleepSync(RETRY_MS);
    nums = findPrs();
  }
  if (!nums.length) {
    skip(`no PR found for ${HEAD_SHA}`);
    return;
  }

  // `sha:` can match more than one PR (a commit reused across PRs/branches).
  // Select the PR whose head commit IS the trigger's head SHA; that is the one
  // that was actually merged. Never blindly trust items[0].
  let pr = '';
  let j = null;
  for (const cand of nums) {
    let c;
    try {
      c = JSON.parse(gh(['api', `repos/${SOURCE_REPO}/pulls/${cand}`]));
    } catch {
      continue;
    }
    if (c.head && c.head.sha === HEAD_SHA) {
      pr = cand;
      j = c;
      break;
    }
  }
  if (!j) {
    skip(`no PR whose head is ${HEAD_SHA} (candidates: ${nums.join(',') || 'none'})`);
    return;
  }

  const merged = j.merged === true;
  const base = j.base && j.base.ref;
  const sha = j.merge_commit_sha;
  const login = (j.user && j.user.login) || '';
  if (!merged || base !== BASE_REF || !sha) {
    skip(`PR #${pr} is not a merged ${BASE_REF} PR`);
    return;
  }

  console.log(`Resolved merged PR #${pr} (merge ${sha})`);
  setOutputs({ proceed: true, pr, sha, login });
}

main();
