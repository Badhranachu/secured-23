# External Security Review Handoff

This file is the safe checklist to share with an external reviewer who will inspect:

- malware or secret exposure in GitHub repositories
- API security and endpoint behavior
- server posture and deployment access
- domain-level security issues

Do not commit live passwords, personal access tokens, SSH private keys, or production secrets into this repository. Fill sensitive values only in a secure out-of-band channel such as a password manager, encrypted note, or one-time secret link.

## 1. Required Review Inputs

Fill these fields before handing the project to an external reviewer:

### Application Identity

- Project name:
- Target domain:
- Public app URL:
- API base URL:
- Environment under review: `local` / `staging` / `production`

### GitHub Repositories

- Main repository URL:
- Frontend repository URL:
- Backend repository URL:
- Default branch:
- Commit or tag to review:

### Test Access For API Checks

- Test user email:
- Test user role:
- Test user password:
  Share out-of-band only.
- Test bearer token:
  Share out-of-band only.
- MFA required: `yes` / `no`
- Known protected endpoints to validate:

### Server Access

- Server IP address:
- Server hostname:
- SSH port:
- SSH username:
- SSH password or private key passphrase:
  Share out-of-band only.
- Hosting provider:
- Reverse proxy / web server: `nginx` / `apache` / other
- Process manager: `systemd` / `pm2` / `docker` / other

### Database And Queue

- Database host:
- Database name:
- Redis host:
- Celery enabled: `yes` / `no`

### Reviewer Scope

- Check GitHub repositories for malware or hidden backdoors: `yes` / `no`
- Check all documented APIs: `yes` / `no`
- Check auth flow and JWT handling: `yes` / `no`
- Check server for suspicious processes/files: `yes` / `no`
- Check public domain security headers/TLS/DNS: `yes` / `no`

## 2. Current Project Defaults Found In Code

These are local/demo values discovered in the repository and should not be treated as production credentials:

- Frontend default API URL: `http://127.0.0.1:8000/api/v1`
- Demo admin email: `admin@aegis.local`
- Demo admin password: `Admin123!`
- Demo user email: `demo@aegis.local`
- Demo user password: `Demo123!`
- Seeded demo domain: `example.com`
- Seeded demo frontend repo: `https://github.com/octocat/Hello-World`
- Seeded demo backend repo: `https://github.com/octocat/Spoon-Knife`

If this handoff is for a real server, replace those demo values with the real environment details before review.

## 3. API Areas To Review

Backend routes are mounted under `http://127.0.0.1:8000/api/v1` by default.

### Health

- `/health/`

### Auth

- `/auth/register/`
- `/auth/login/`
- `/auth/refresh/`
- `/auth/logout/`
- `/auth/profile/`
- `/auth/forgot-password/`
- `/auth/users/`

### Projects

- `/projects/`
- `/projects/{id}/scan-now/`
- `/projects/{id}/toggle-schedule/`
- `/projects/{id}/latest-scan/`
- `/projects/{id}/scan-history/`

### Scans

- `/scans/results/`
- `/scans/results/{id}/`
- `/scans/results/{id}/rerun/`
- `/scans/results/{id}/generate-report/`
- `/scans/results/{id}/compare-report/`
- `/scans/results/{id}/accept-and-push/`
- `/scans/vulnerabilities/`

### Reports

- `/reports/`
- `/reports/generate/`
- `/reports/{id}/download/`

### Dashboard

- `/dashboard/user-summary/`
- `/dashboard/admin-summary/`

### Domain Scans

- `/domain-scans/`
- `/domain-scans/scan/`
- `/domain-scans/{id}/findings/`
- `/domain-scans/dashboard-summary/`

## 4. Important Security Notes From This Review

- The project stores test passwords and access tokens encrypted in the database, and only exposes flags or masked token values through the serializer.
- A real security issue was found in the GitHub push workflow: authenticated GitHub URLs were being written to application logs. The code has been patched to redact token-bearing URLs before logging.
- `backend/logs/app.log` may still contain previously written sensitive URLs from older runs. Clean or rotate that log before sharing the environment with anyone else.

## 5. Safe Sharing Rule

Share these items only through a secure secret-sharing method, not in Git, chat, screenshots, or plaintext docs:

- production passwords
- GitHub personal access tokens
- SSH passwords
- SSH private keys
- database passwords
- `.env` values
