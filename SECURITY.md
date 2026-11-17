# Security policy

## Reporting vulnerabilities

Open a GitHub issue with a minimal description and request coordinated follow-up. Do not include exploit details, live credentials, private deployment details, or customer/project data. Include the affected revision and a safe impact summary.

## Deployment trust boundary

PR code is effectively root on the host and can read every stored credential. CI workers use privileged Docker-in-Docker and share the host kernel. Enable only repositories and contributors you would trust with host-root access; review dependency-bot changes before running them. Fork PRs are not executed, but that does not make same-repository code safe.

Use a dedicated single-user host. Keep the backend bound to loopback behind the documented authenticated ingress. Any local user or container able to reach port 8787 can forge the identity header. An alternative ingress must strip client-supplied identity headers and insert the authenticated `Tailscale-User-Login` value itself.

Use narrow credentials. The optional host GitHub login is not permission-narrowed by workflow YAML. Keep the Docker socket, runtime token, database encryption key, backups, and provider credentials out of public artifacts and logs.

## Supported versions

Security fixes are applied to the latest commit on `main`. Older commits and local forks should be reviewed and upgraded by their operators.
