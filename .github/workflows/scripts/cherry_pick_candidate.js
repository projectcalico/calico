// Reconciles the `cherry-pick-candidate` label on master PRs based on an
// external LLM classifier agent's verdict. Invoked from the Stage 2
// cherry-pick-candidate workflow via actions/github-script.
//
// Rules:
//   agent says backport, label absent       : add label
//   agent says skip, label present (by bot) : remove label
//   any non-bot action on the label         : leave it alone (for the
//                                             rest of the PR's life)
//
// The whole job is a no-op until the BACKPORT_CLASSIFIER_AGENT_URL and
// BACKPORT_CLASSIFIER_AGENT_TOKEN repo secrets are set (passed in to
// this script as AGENT_URL and AGENT_TOKEN env vars by the workflow).

const LABEL = 'cherry-pick-candidate';
const BOT_LOGIN = 'github-actions[bot]';

module.exports = async ({ github, context, core }) => {
  const { owner, repo } = context.repo;
  const agentUrl = process.env.AGENT_URL;
  const agentToken = process.env.AGENT_TOKEN;
  if (!agentUrl || !agentToken) {
    core.warning('BACKPORT_CLASSIFIER_AGENT_URL or BACKPORT_CLASSIFIER_AGENT_TOKEN secret missing (read by this script as AGENT_URL/AGENT_TOKEN env vars), skipping');
    return;
  }
  // Register the token for log masking so it cannot leak via any
  // downstream log line, including diagnostics added later.
  core.setSecret(agentToken);
  // Refuse to send the bearer token over plaintext if a misconfigured
  // secret points at a non-https URL.
  if (!/^https:\/\//i.test(agentUrl)) {
    core.warning('AGENT_URL is not https://, refusing to send bearer token over plaintext, skipping');
    return;
  }
  // Neutralize :: in agent-controlled text before logging so the agent
  // cannot inject ::add-mask:: or other workflow commands. Used for every
  // line that echoes any byte the agent could have authored.
  const safe = s => String(s ?? '').replace(/::/g, ':​:');

  const headSha = context.payload.workflow_run?.head_sha;
  if (!headSha) {
    core.warning('workflow_run payload missing head_sha, skipping');
    return;
  }

  // 1. Find the open master PR for this head SHA.
  const associated = await github.paginate(
    github.rest.repos.listPullRequestsAssociatedWithCommit,
    { owner, repo, commit_sha: headSha },
  );
  const pr = associated.find(p =>
    p.state === 'open' && p.head.sha === headSha && p.base.ref === 'master',
  );
  if (!pr) {
    core.warning(`no open master PR found with head SHA ${headSha}, skipping`);
    return;
  }

  // 2. Authority check. The most recent labeled/unlabeled event for this
  //    label tells us who currently owns it. Any actor other than
  //    github-actions[bot] is final.
  const events = await github.paginate(
    github.rest.issues.listEventsForTimeline,
    { owner, repo, issue_number: pr.number },
  );
  const labelEvents = events.filter(e =>
    (e.event === 'labeled' || e.event === 'unlabeled') && e.label?.name === LABEL,
  );
  const lastActor = labelEvents[labelEvents.length - 1]?.actor?.login || '';
  if (lastActor && lastActor !== BOT_LOGIN) {
    core.info(`Label authority: ${lastActor} (non-bot), bot will not modify`);
    return;
  }
  const present = pr.labels.some(l => l.name === LABEL);
  core.info(`Label authority: bot (last actor: ${lastActor || 'none'}, present=${present})`);

  // 3. Call the classifier agent. Up to 3 attempts with 5s, 10s backoff.
  const msgId = `calico-backport-classifier-${pr.number}-${process.env.GITHUB_RUN_ID}`;
  const payload = {
    jsonrpc: '2.0',
    id: msgId,
    method: 'message/send',
    params: {
      message: {
        messageId: msgId,
        role: 'user',
        parts: [{
          kind: 'text',
          text: `PR number: ${pr.number}\nPR title: ${pr.title}\nPR body:\n${pr.body || ''}`,
        }],
      },
      configuration: { acceptedOutputModes: ['application/json', 'text/plain'] },
    },
  };

  let response = null;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const r = await fetch(agentUrl, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${agentToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
        // Fail closed on any redirect so the bearer token cannot be
        // sent to a different host than the configured AGENT_URL.
        redirect: 'error',
        signal: AbortSignal.timeout(60_000),
      });
      if (r.ok) {
        response = await r.json();
        break;
      }
      core.info(`agent attempt ${attempt} failed (http=${r.status})`);
    } catch (e) {
      core.info(`agent attempt ${attempt} failed (${e.message})`);
    }
    if (attempt < 3) await new Promise(res => setTimeout(res, attempt * 5000));
  }
  if (!response) {
    core.warning('agent unreachable after 3 attempts, skipping');
    return;
  }

  // 4. Parse the response. Contract: result.artifacts[0].parts[0].text is
  //    a JSON object with fields decision (backport|skip), confidence,
  //    primary_signal, reason. Tolerated wrapped in a markdown fence.
  const raw = response.result?.artifacts?.[0]?.parts?.[0]?.text || '';
  const stripped = raw.replace(/^```(?:json)?\s*\n?|\n?```\s*$/gm, '').trim();
  let parsed;
  try {
    parsed = JSON.parse(stripped);
  } catch (e) {
    core.warning(`could not parse agent response: ${e.message}`);
    core.info(safe(`raw response: ${JSON.stringify(response).slice(0, 500)}`));
    return;
  }
  const { decision, confidence, primary_signal: primarySignal, reason } = parsed;
  if (decision !== 'backport' && decision !== 'skip') {
    core.warning(`unknown decision: ${decision}, skipping`);
    return;
  }
  core.info(`agent decision: ${decision} (confidence=${safe(confidence)})`);
  core.info(`primary signal: ${safe(primarySignal)}`);
  core.info(`reason: ${safe(reason)}`);

  // 5. Reconcile. addLabels is idempotent server-side; removeLabel 404s if
  //    the label was removed by a human during the agent call (we treat
  //    that as a no-op since the end state matches our intent).
  if (decision === 'backport' && !present) {
    core.info(`Adding ${LABEL} to PR #${pr.number}`);
    await github.rest.issues.addLabels({
      owner, repo, issue_number: pr.number, labels: [LABEL],
    });
  } else if (decision === 'skip' && present) {
    core.info(`Removing ${LABEL} from PR #${pr.number} (bot-applied, agent now says skip)`);
    try {
      await github.rest.issues.removeLabel({
        owner, repo, issue_number: pr.number, name: LABEL,
      });
    } catch (e) {
      if (e.status === 404) {
        core.info('label already gone, no-op');
      } else {
        throw e;
      }
    }
  } else {
    core.info(`No-op (decision=${decision}, present=${present})`);
  }
};
