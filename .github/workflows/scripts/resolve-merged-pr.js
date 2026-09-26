// Resolves the PR whose merge commit is the pushed MERGE_SHA; a direct push
// has none. Writes outputs proceed/pr/sha/login/merger/trusted.
//
// Env:
//   SOURCE_REPO       owner/name the PR lives in.
//   MERGE_SHA         the pushed commit (github.sha).
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

// Returns the PRs whose merge commit is MERGE_SHA (empty on miss or API error).
function findPrs() {
  try {
    const prs = JSON.parse(gh(['api', `repos/${SOURCE_REPO}/commits/${MERGE_SHA}/pulls`]));
    return prs.filter((p) => p.merge_commit_sha === MERGE_SHA);
  } catch {
    return [];
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
  if (!SOURCE_REPO || !MERGE_SHA) {
    skip('SOURCE_REPO or MERGE_SHA unset');
    return;
  }

  let prs = findPrs();
  if (!prs.length) {
    // The commit->PR association can lag a few seconds behind a merge; retry once.
    sleepSync(RETRY_MS);
    prs = findPrs();
  }
  if (!prs.length) {
    // A direct push (no PR) lands here too.
    skip(`no PR merged as ${MERGE_SHA}`);
    return;
  }

  // The list endpoint omits merged/merged_by, so read the full PR.
  const pr = String(prs[0].number);
  let j;
  try {
    j = JSON.parse(gh(['api', `repos/${SOURCE_REPO}/pulls/${pr}`]));
  } catch {
    skip(`could not read PR #${pr}`);
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

  const merger = (j.merged_by && j.merged_by.login) || '';
  const trusted = isOrgMember(login);
  console.log(`Resolved merged PR #${pr} (merge ${sha}, author ${login}, ` +
    `${env.MEMBER_ORG || 'org'} member: ${trusted})`);
  setOutputs({ proceed: true, pr, sha, login, merger, trusted });
}

main();
