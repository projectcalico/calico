// Slack DM notifier for the auto-pick workflow. Reusable across flows: the
// caller passes everything via env. DMs the original PR author that their
// change was cherry-picked. Soft-fail by design: it never throws fatally, so a
// Slack hiccup or an unmapped author can't fail the job.
//
// Env:
//   SLACK_BOT_TOKEN  Slack bot token (needs chat:write). DM is sent by posting
//                    chat.postMessage with channel=<user-id> directly, like the
//                    merge-queue-bot (no conversations.open / im:write needed).
//   PICK_NOTIFY_MAP  "login:slack-id,login:slack-id,..." opt-in map.
//   AUTHOR_LOGIN     GitHub login of the original PR author.
//   SOURCE_REPO, SRC_PR   The source repo and PR number. SRC_URL is derived
//                    from them, and SRC_TITLE is fetched via `gh` (best-effort),
//                    unless either is passed in explicitly.
//   EE_PR_URL        The created cherry-pick PR URL.
//   OUTCOME          'clean' | 'conflict' (drives the review note).
//   CONFLICT_SEVERITY 'light' | 'heavy' (conflict picks; shown in the DM).
//   MODE             'picked' (default) | 'escalated'.
//   ESCALATION_REASON short reason string (escalated mode).
//   RUN_URL          workflow run URL (escalated mode; link for the human).
//   TARGET_LABEL     Human label for the target (e.g. "Enterprise").
//   TARGET_BRANCH    Target branch (e.g. "master").

const { execFileSync } = require('node:child_process');

const env = process.env;

function slackIdFor(login, map) {
  for (const entry of map.split(',')) {
    const s = entry.trim();
    const i = s.indexOf(':');
    if (i < 0) continue;
    if (s.slice(0, i).trim() === login) return s.slice(i + 1).trim();
  }
  return '';
}

async function main() {
  const token = env.SLACK_BOT_TOKEN;
  const map = env.PICK_NOTIFY_MAP;
  if (!token || !map) {
    console.log('::notice::Slack token or PICK_NOTIFY_MAP unset -- skipping');
    return;
  }

  const author = env.AUTHOR_LOGIN || '';
  const slackId = slackIdFor(author, map);
  if (!slackId) {
    console.log(`::notice::author ${author} not in PICK_NOTIFY_MAP -- skipping`);
    return;
  }

  const label = env.TARGET_LABEL || 'Enterprise';
  const branch = env.TARGET_BRANCH || 'master';
  const targetPlain = `${label} \`${branch}\``;

  // Derive the source PR URL and title here (once) instead of in every caller.
  const server = env.GITHUB_SERVER_URL || 'https://github.com';
  const srcUrl = env.SRC_URL
    || (env.SOURCE_REPO && env.SRC_PR ? `${server}/${env.SOURCE_REPO}/pull/${env.SRC_PR}` : '');
  let srcTitle = env.SRC_TITLE || '';
  if (!srcTitle && env.SOURCE_REPO && env.SRC_PR) {
    try {
      srcTitle = execFileSync('gh',
        ['api', `repos/${env.SOURCE_REPO}/pulls/${env.SRC_PR}`, '--jq', '.title'],
        { encoding: 'utf8' }).trim();
    } catch { /* best-effort; the DM is still useful without the title */ }
  }
  const title = srcTitle.replace(/[<>|*]/g, '').trim();
  const titlePart = title ? ` *${title}*` : '';
  // Line 1: "#<num> 【OS】 【PR】 <title>" where 【OS】 links to the source PR and
  // 【PR】 to the cherry-pick PR, matching the team's PR-list link tags.
  const osTag = `<${srcUrl}|【OS】>`;

  // Line 1 carries no icon; the result icon sits on the status line below,
  // next to the resolution text.
  let text;
  if (env.MODE === 'escalated') {
    const reason = (env.ESCALATION_REASON || 'needs manual resolution').replace(/[<>|*]/g, '').trim();
    const lines = [
      `#${env.SRC_PR} ${osTag}${titlePart}`,
      `:warning:  Your OSS PR could NOT be auto-cherry-picked to ${targetPlain}.`,
      `*Reason:*  ${reason}.`,
    ];
    if (env.RUN_URL) lines.push(`<${env.RUN_URL}|See the run>.`);
    text = lines.join('\n');
  } else if (env.MODE === 'noop') {
    const lines = [
      `#${env.SRC_PR} ${osTag}${titlePart}`,
      `:information_source:  Nothing to cherry-pick to ${targetPlain}: the change is already present or was superseded.`,
    ];
    if (env.RUN_URL) lines.push(`<${env.RUN_URL}|See the run>.`);
    text = lines.join('\n');
  } else {
    const prTag = env.EE_PR_URL ? ` <${env.EE_PR_URL}|【PR】>` : '';
    const review = env.EE_PR_URL ? `<${env.EE_PR_URL}|Please review>` : 'Please review';
    const lines = [
      `#${env.SRC_PR} ${osTag}${prTag}${titlePart}`,
      `:cherries:  Your OSS PR has been auto-cherry-picked to ${targetPlain}.`,
    ];
    if (env.OUTCOME === 'conflict') {
      const sev = (env.CONFLICT_SEVERITY || '').toLowerCase();
      if (sev === 'heavy') lines.push(`:warning:  Heavy conflict, AI-resolved. ${review} closely.`);
      else if (sev === 'light') lines.push(`:eyes:  Light conflict, AI-resolved. ${review}.`);
      else lines.push(`:eyes:  Conflict, AI-resolved. ${review}.`);
    }
    text = lines.join('\n');
  }

  let data;
  try {
    const resp = await fetch('https://slack.com/api/chat.postMessage', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json; charset=utf-8',
      },
      body: JSON.stringify({ channel: slackId, text, unfurl_links: false }),
      signal: AbortSignal.timeout(30000),
    });
    data = await resp.json();
  } catch (err) {
    console.log(`::warning::Slack request failed: ${err.message}`);
    return;
  }

  if (data && data.ok) {
    console.log(`DM sent to ${author} (${slackId})`);
  } else {
    console.log(`::warning::Slack DM failed: ${(data && data.error) || 'unknown'}`);
  }
}

main().catch((err) => {
  // Never fail the job on a notifier bug.
  console.log(`::warning::notify-slack error: ${err.message}`);
});
