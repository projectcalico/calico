// Resolves the merged PR to cherry-pick and writes outputs
// proceed/pr/sha/login/merger/trusted. Two entry points:
//   - MERGE_SHA  (automatic push): find the PR whose merge commit is this pushed
//                commit; a direct push has none, which is a normal quiet no-op.
//   - PR_NUMBER  (manual dispatch): the PR is named directly, so skip the
//                commit->PR lookup. A manual request is explicit, so a bad or
//                unmerged number fails loudly instead of skipping.
// Give exactly one. The same merged/base/skip-label/trusted checks run for both.
//
// Env:
//   SOURCE_REPO       owner/name the PR lives in.
//   MERGE_SHA         the pushed commit (github.sha) -- automatic push.
//   PR_NUMBER         an already-merged PR number -- manual dispatch.
//   BASE_REF          required base branch (default "master").
//   GH_TOKEN          token for `gh` (set by the caller).
//   MEMBER_ORG        org whose members count as trusted PR authors.
//   MEMBER_TOKEN      token that can see MEMBER_ORG's private memberships.
//   RESOLVE_RETRY_MS  retry delay for API lag after a merge (default 5000).
//   GITHUB_OUTPUT     set by Actions; falls back to stdout for local runs.

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');

const env = process.env;
const SOURCE_REPO = env.SOURCE_REPO || '';
const MERGE_SHA = env.MERGE_SHA || '';
const PR_NUMBER = env.PR_NUMBER || '';
const BASE_REF = env.BASE_REF || 'master';
const RETRY_MS = Number(env.RESOLVE_RETRY_MS ?? 5000);

function gh(args, extraEnv = {}) {
  return execFileSync('gh', args, { encoding: 'utf8', env: { ...env, ...extraEnv } });
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

// Returns the PRs whose merge commit is MERGE_SHA, or null if the lookup itself
// failed. null is not the same as an empty list: a failed call must not be read
// as "no PR" and silently skip a real merged PR.
function findPrs() {
  try {
    const prs = JSON.parse(gh(['api', `repos/${SOURCE_REPO}/commits/${MERGE_SHA}/pulls`]));
    return prs.filter((p) => p.merge_commit_sha === MERGE_SHA);
  } catch {
    return null;
  }
}

// Gates on the author, who writes the text the agent reads. Any error means untrusted.
function isOrgMember(login) {
  if (!login || !env.MEMBER_ORG || !env.MEMBER_TOKEN) return false;
  try {
    gh(['api', `orgs/${env.MEMBER_ORG}/members/${login}`, '--silent'],
      { GH_TOKEN: env.MEMBER_TOKEN });
    return true;
  } catch {
    return false;
  }
}

function main() {
  if (!SOURCE_REPO) {
    skip('SOURCE_REPO unset');
    return;
  }

  // manual = a dispatch named a PR directly; such a request is explicit, so a
  // bad or unmerged number fails loudly rather than skipping quietly.
  const manual = PR_NUMBER !== '';
  let pr;
  if (manual) {
    if (!/^[0-9]+$/.test(PR_NUMBER)) {
      console.log('::error::PR_NUMBER must be a number');
      process.exit(1);
    }
    pr = String(PR_NUMBER);
  } else {
    if (!MERGE_SHA) {
      skip('neither PR_NUMBER nor MERGE_SHA set');
      return;
    }
    // The commit->PR association can lag a few seconds behind a merge, and the
    // API can blip; try again once on either an empty result or a failed lookup.
    let prs = findPrs();
    if (prs === null || !prs.length) {
      sleepSync(RETRY_MS);
      prs = findPrs();
    }
    if (prs === null) {
      // The lookup failed (not "no PR"): fail loudly so a transient API error
      // cannot silently drop a real merged PR.
      console.log(`::error::could not look up the PR for commit ${MERGE_SHA}; failing rather than skipping`);
      process.exit(1);
    }
    if (!prs.length) {
      // A direct push (no PR) lands here too.
      skip(`no PR merged as ${MERGE_SHA}`);
      return;
    }
    pr = String(prs[0].number);
  }

  // Read the full PR for merged/base/merge_commit_sha/author/labels (the list
  // endpoint omits merged/merged_by).
  let j;
  try {
    j = JSON.parse(gh(['api', `repos/${SOURCE_REPO}/pulls/${pr}`]));
  } catch {
    console.log(`::error::could not read PR #${pr}; failing rather than skipping`);
    process.exit(1);
  }
  const merged = j.merged === true;
  const base = j.base && j.base.ref;
  const sha = j.merge_commit_sha;
  const login = (j.user && j.user.login) || '';
  if (!merged || base !== BASE_REF || !sha) {
    const msg = `PR #${pr} is not a merged ${BASE_REF} PR`;
    // A manual dispatch named this PR on purpose, so fail loudly; an automatic
    // run reaching here is a normal no-op.
    if (manual) {
      console.log(`::error::${msg}`);
      process.exit(1);
    }
    skip(msg);
    return;
  }

  // Opt-out: the skip-bot-cherry-pick label means "do not pick this PR". Gate
  // here, before any clone or cherry-pick, and stay silent (no DM).
  const labels = (j.labels || []).map((l) => l && l.name);
  if (labels.includes('skip-bot-cherry-pick')) {
    skip(`PR #${pr} has the skip-bot-cherry-pick label`);
    return;
  }

  const merger = (j.merged_by && j.merged_by.login) || '';
  const trusted = isOrgMember(login);
  console.log(`Resolved merged PR #${pr} (merge ${sha}, author ${login}, ` +
    `${env.MEMBER_ORG || 'org'} member: ${trusted})`);
  setOutputs({ proceed: true, pr, sha, login, merger, trusted });
}

main();
