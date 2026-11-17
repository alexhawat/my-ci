# Security policy

## Reporting vulnerabilities

Report vulnerabilities privately through GitHub private vulnerability reporting for this repository: open the **Security** tab and choose **Report a vulnerability** (<https://github.com/alexhawat/my-ci/security/advisories/new>). Include the affected revision and an impact summary. Do not open public issues for unpatched vulnerabilities, and do not include live credentials, private deployment details, or customer/project data in any report.

If the **Report a vulnerability** button is unavailable, open an issue that only asks the maintainer to enable private vulnerability reporting, with no vulnerability details.

## Deployment trust boundary

PR code is effectively root on the host and can read every stored credential. CI workers use privileged Docker-in-Docker and share the host kernel. Each run has its own Docker bridge network, which isolates concurrent runs from each other over the network but is not a host boundary. Enable only repositories and contributors you would trust with host-root access. Fork PRs are not executed, but that does not make same-repository code safe.

Bot-authored PRs (GitHub user type `Bot` or a login ending in `[bot]`) are not run automatically: Local CI records a blocked run awaiting operator approval, and the operator starts it from the dashboard after reviewing the change. The per-repository `run_bot_prs` setting (off by default) restores automatic runs and should stay off unless you trust that bot's changes with host-root access.

Use a dedicated single-user host. Keep the backend bound to loopback behind the documented authenticated ingress. Any local user or container able to reach port 8787 can forge the identity header. An alternative ingress must strip client-supplied identity headers and insert the authenticated `Tailscale-User-Login` value itself.

Use narrow credentials. Each workflow's secrets file holds only the secrets it references and exists in the worker only while it runs; this limits exposure but is not a sandbox, since jobs of a workflow share it and PR code can read the data volume. GitHub App credentials are not passed to CI or review containers but are stored in that volume. The optional host GitHub login is not permission-narrowed by workflow YAML, and once `login.sh` has run its token file exists on the host whether or not a repository enables it; use a dedicated low-privilege GitHub account. Keep the Docker socket, runtime token, database encryption key, backups, and provider credentials out of public artifacts and logs.

## Supported versions

Security fixes are applied to the latest commit on `main`. Older commits and local forks should be reviewed and upgraded by their operators.
