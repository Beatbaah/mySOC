# Security design

mySOC holds sensitive data (who talks to whom, which hosts are compromised, API keys), so it's built to
the standard expected of the tools that protect everything else.

## Authentication

- **No default credentials.** The first admin gets either a password from `MYSOC_BOOTSTRAP_ADMIN_PASSWORD`
  (checked against the password policy) or a random one-time password printed once in the API log, which must
  be changed at first sign-in. New users get one-time passwords the same way.
- **Passwords** are hashed with Argon2id and rehashed automatically when parameters change. The policy follows
  NIST SP 800-63B: length (12+), a block list, no username; no arbitrary complexity rules.
- **Two-step verification (TOTP, RFC 6238)** is mandatory for admins (enforced at sign-in, before any other
  endpoint works) and available to everyone. Secrets are encrypted at rest, and each code's time step is
  recorded so a code can't be replayed. Enrolling ends the user's other sessions.
- **Brute force:** failed attempts are throttled per client IP (5 per 5 minutes) and lock the account for 15
  minutes after 5 failures. Unknown users, wrong passwords and locked accounts all get the same message and a
  real hash check, so responses don't reveal which usernames exist.

## Sessions

- A random 256-bit token in an `HttpOnly`, `SameSite=Strict` cookie (`Secure` over HTTPS). Only its SHA-256 is
  stored, so a database leak doesn't hand out live sessions.
- 30-minute idle timeout and 12-hour absolute lifetime. A half-finished sign-in (password accepted, code not
  yet entered) is valid for 10 minutes and can't call anything but the code endpoints.
- Changing a password, resetting 2-step, changing a role or disabling an account ends that user's sessions.
  The live-update stream re-checks the session every few seconds and closes when it ends.
- **CSRF:** every state-changing request needs the session's CSRF token in a header, on top of SameSite=Strict
  and JSON-only bodies.

## Authorisation

Three roles, checked on the server for every endpoint: **viewer** (read-only), **analyst** (triage, cases,
hunts, indicators, assets), **admin** (people, rules, settings, audit log). The last active admin can't be
demoted or disabled. Accounts flagged to change their password can't do anything else until they do.

## Data handling

- **Secrets** (provider API keys, SMTP password, Telegram token) are encrypted with Fernet using
  `MYSOC_VAULT_KEY`, are write-only through the API, and their values never appear in logs or the audit trail.
  Production refuses to start without the key; development generates a local key file readable only by the
  current user.
- **Input** is validated with typed models and bounded sizes. Database access goes through SQLAlchemy with
  bound parameters only. Hunts are pre-built and parameterised: there's no free-form query interface. Rule
  parameters are type- and range-checked against each rule's defaults.
- **Outbound requests** go only to the configured intel providers and notification services, with validated,
  percent-encoded indicators, timeouts and redirects disabled. The sensor never calls out to look up the
  addresses it sees.
- **CSV exports** neutralise spreadsheet formulas.
- **Retention:** flows 7 days, logs 30 days, closed alerts 180 days by default.

## Web and deployment

- The console is served with a strict Content Security Policy (scripts from self only, no inline scripts),
  `frame-ancestors 'none'`, `nosniff`, `no-referrer` and a restrictive Permissions-Policy. Fonts are bundled, so
  the console makes no third-party requests. API responses are `no-store` with `default-src 'none'`.
- Containers run as non-root users with read-only filesystems, `no-new-privileges` and all capabilities
  dropped. Live capture adds only `NET_RAW`/`NET_ADMIN`. The API and database aren't published; only nginx is.
- `MYSOC_ENV=production` refuses to start without HTTPS, a vault key, or with admin 2-step disabled, and turns
  off the interactive API docs.

## Audit

Sign-ins (successful and failed), lockouts, 2-step changes, every alert/case/rule/asset/indicator change,
exports, intel lookups, hunts and settings changes are recorded with the actor and client IP.

## Reporting a vulnerability

Please open a private security advisory on the GitHub repository rather than a public issue.
