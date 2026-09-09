# Using AI tools to contribute to Calico

AI tools are welcome here. Plenty of us use them. This policy sets the floor for using them on contributions to this repository - code, docs, issues, and reviews alike. It is deliberately short, and it borrows heavily from the Kubernetes project's [approach to the same problem](https://kubernetes.io/blog/2026/06/26/open-source-maintainership-in-the-age-of-ai/).

## You are responsible for your change

The person who opens a pull request owns every line in it, whether they typed it or an agent did. "That's what the AI generated" is not an answer to review feedback.

## Say when AI helped

Note it in the PR description. One line is enough:

> This PR was written in part with the assistance of generative AI.

Don't credit AI tools as commit co-authors (`Co-Authored-By:`, `Assisted-By:`, and similar trailers). Our CLA is an agreement between humans, and a co-author who can't sign it will block your PR.

## Reviews happen between humans

Reviewers are here to talk to you, not to your agent. You need to be able to explain what your change does and why, in your own words. If you can't, expect the reviewer to close the PR.

Using an agent to help draft a reply is fine. Handing over the review thread to one is not.

## Understand it before you push

Working code isn't the bar - understood code is. Before you open the PR:

- read the whole diff yourself, including the parts you didn't write
- run the tests that cover the change, and add tests for new behavior
- confirm generated files came out of `make generate` rather than being hand-edited
- check that the change fits the design docs for the components it touches, and update them if it doesn't

Agents are especially prone to inventing plausible-looking tests that assert nothing, and to "fixing" a test by loosening its assertion. Read your test diffs closely.

## Automated review bots

Comments from review bots are advisory. A human maintainer still approves and merges, and you're free to disagree with a bot and say why.
