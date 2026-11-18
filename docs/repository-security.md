# Repository access and merge control

This repository is public. Public means anyone can read it, fork it, open
issues and open pull requests from a fork. It does not mean anyone can change
it: pushing, merging and reading secrets all require write access, and the only
account with access is the owner.

## Who can do what

| Action | Anyone on GitHub | Owner (`@alexhawat`) |
|--------|------------------|----------------------|
| Read code, fork, open issues | yes | yes |
| Open a pull request | from a fork only | from a branch or a fork |
| Push a branch to this repository | no | yes |
| Push directly to `main` | no | no, once the ruleset is active |
| Merge a pull request | no | yes, when the required checks pass |
| Read or use Actions secrets | no | workflows on branches in this repository |
| Trigger a paid mergeCraft review | no | yes, by opening a pull request from a branch here |

## What the workflows enforce

- **`CI`** (`.github/workflows/ci.yml`) runs on `pull_request` with a read-only
  token and no secrets, so it is safe to run on fork pull requests. It lints
  the workflows (actionlint, zizmor), scans history for secrets (gitleaks),
  reviews dependency changes, and runs the Python and JavaScript checks from
  `TESTING.md` when those sources exist. `CI gate` is the one check to require.
- **`CodeQL`** (`.github/workflows/codeql.yml`) scans workflows, Python and
  JavaScript, for whichever of them exist on the ref.
- **`mergeCraft`** (`.github/workflows/mergecraft.yml`) reviews pull requests
  with Claude Sonnet 5.5 and reports the `mergeCraft review` check.

## How the mergeCraft review is contained

The review runs on `pull_request_target`, which has repository secrets in
scope, so these properties matter:

- **The workflow and its config come from `main`**, not from the pull request.
  A pull request that edits `mergecraft.yml` or `.mergecraft/config.yaml` is
  reviewed by the versions already on `main`; its edits apply from the next
  pull request on.
- **Pull request code is never executed.** `actions/checkout` takes the default
  branch. The Action is pinned by commit SHA and runs with `push: disabled`,
  `shell: disabled` and `analyzers: untrusted-only`.
- **Fork pull requests get no secret and no review.** The same-repo guard
  withholds `ANTHROPIC_API_KEY`, so a stranger cannot spend the API budget or
  reach the key. The `mergeCraft review` check then fails, and merging that
  pull request takes a deliberate owner bypass after a manual read.
- **There is no comment trigger.** Nobody can start a run or hand the reviewer
  a prompt by commenting.
- **The reviewer cannot approve or merge.** `prApproveEnabled` and
  `autoMergeEnabled` are false. It posts comments and a check; the check is
  computed from typed findings, not from what the model says.
- **Each job holds the least token scope it needs.** The wait job can only
  read check-runs; only the review job can write comments and checks.
- **Dependabot pull requests are gated by CI only.** GitHub withholds Actions
  secrets from them, so they cannot be reviewed; the review job passes with a
  warning for `dependabot[bot]` and fails for everyone else without a review.

`trust.selfReview` is `full` in `.mergecraft/config.yaml`. Under
`pull_request_target` mergeCraft treats every run as untrusted otherwise, and
an untrusted run can only conclude `neutral`, which the workflow counts as
blocking. `full` lets a pull request from a branch in this repository reach
`success`. It does not apply to forks.

## Settings that live outside the tree

These cannot be set from a pull request. Do them once, in this order.

1. **Add the secret.** Settings → Secrets and variables → Actions → new
   repository secret `ANTHROPIC_API_KEY`. Use a key with a spend limit.
2. **Merge the workflows to `main`.** `pull_request_target` only runs the copy
   on the default branch, so the first reviewed pull request is the one opened
   after this lands.
3. **Import the ruleset.** Settings → Rules → Rulesets → New ruleset → Import a
   ruleset → `.github/rulesets/protect-main.json`. It requires a pull request
   for every change to `main`, blocks force pushes and deletion, requires
   resolved review threads, and requires `CI gate` and `mergeCraft review`
   from GitHub Actions on an up-to-date branch. The owner can bypass it, on a
   pull request only.
4. **Actions → General.**
   - Fork pull request workflows: require approval for all external
     contributors.
   - Workflow permissions: read repository contents only; leave "Allow GitHub
     Actions to create and approve pull requests" off.
5. **Advanced Security.** Turn on secret scanning with push protection,
   Dependabot alerts and private vulnerability reporting.

## What this does not cover

- **A required check is matched by name.** A pull request that adds a workflow
  with a job called `CI gate` or `mergeCraft review` can report that name. Only
  the owner can merge, so read workflow changes in any pull request you did not
  write before merging it, and approve fork workflow runs only after looking at
  the diff.
- **Nobody approves the owner's pull requests.** With one account there is no
  second human reviewer; the ruleset requires zero approvals for that reason.
  mergeCraft handles this in its own repository with a second code-owner
  account. If a collaborator is added here, raise the approval count to 1 and
  turn on code-owner review.
- **Write access is the real boundary.** Anyone later given write access can
  push a branch whose workflow reads repository secrets. Moving the API key
  into an environment restricted to `main` would close that.
