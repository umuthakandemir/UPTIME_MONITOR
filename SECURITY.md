# Security Policy

## Reporting a vulnerability

Please do not publish exploit details, credentials, or sensitive logs in a public issue. Contact the repository maintainer privately with a concise description, impact, affected version, and safe reproduction steps.

## Deployment guidance

- Use unique secrets and strong passwords.
- Do not expose PostgreSQL or Redis directly to untrusted networks.
- Use trusted HTTPS and keep the host, container images, and Python dependencies updated.
- Restrict monitor targets and outbound network access to reduce SSRF and internal-network exposure risks.
- Back up data securely and limit access to exported reports and screenshots.
