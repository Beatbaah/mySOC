---
name: run-mysoc
description: Run, start, launch, screenshot, drive or smoke-test the mySOC security console (FastAPI API + demo sensor + React/Vite UI). Use when asked to run mySOC, see a UI change in the real app, take screenshots of a page, triage an alert end-to-end, hit the API with curl, or run its tests.
---

# Run mySOC

mySOC is three processes: the FastAPI API (`:8000`), the sensor (it generates demo traffic and runs the detections) and the
Vite console (`:5173`, which proxies `/api` to the API). `run.sh` starts all three on a **throwaway SQLite DB** in
`$TMPDIR/mysoc-run/`, so the developer's `backend/mysoc-dev.db` and `backend/.env` data are never touched. `driver.mjs`
signs in through the real login form in headless Chromium (Playwright) and screenshots or clicks through pages.

Paths below are relative to the `mySOC/` repo root. Verified on macOS (Darwin, Python 3.12.13 venv, Node 24); no Docker
was available, so the Docker path from the README was **not** verified.

## Prerequisites (one-time)

`backend/.venv` (Python 3.12) and `frontend/node_modules` must exist. If they're missing:

```bash
cd backend && python3.12 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt && cd ..
cd frontend && npm ci && cd ..
```

Driver deps (Playwright 1.49.1 + headless Chromium, ~80 MB into `~/Library/Caches/ms-playwright`):

```bash
cd .claude/skills/run-mysoc && npm install && npx playwright install chromium && cd -
```

## Run (agent path)

```bash
.claude/skills/run-mysoc/run.sh up        # ~5 s; prints URL + login. Fails fast if :8000/:5173 are busy
D=.claude/skills/run-mysoc
node $D/driver.mjs shot / /alerts /traffic          # one PNG per route
node $D/driver.mjs triage                           # queue -> first New alert -> "Take it" -> screenshot
node $D/driver.mjs search "198.51"                  # type in top-bar search, print grouped hits, Enter on the first
MYSOC_THEME=dark node $D/driver.mjs shot /           # pin dark/light (headless defaults to light)
node $D/driver.mjs text /cases                      # visible text of <main>
node $D/driver.mjs eval /alerts 'document.querySelectorAll("tbody tr.clickable").length'
.claude/skills/run-mysoc/run.sh status    # api/sensor/vite running|stopped
.claude/skills/run-mysoc/run.sh logs 30   # tail all three logs
.claude/skills/run-mysoc/run.sh down      # add --wipe to delete the throwaway DB too
```

- Screenshots: `$TMPDIR/mysoc-run/shots/<route>.png` (full page, 1440 wide). `/` saves as `overview.png`. Read them.
- Login: `admin` / `Agent-Run-Passw0rd!x`, with the authenticator (MFA) step turned off (`MYSOC_REQUIRE_MFA_FOR_ADMIN=false`).
  Override with `MYSOC_AGENT_PASSWORD` (it must pass the password policy).
- The driver prints `page errors:` if the console logged errors after sign-in. Treat new ones as regressions.
- Routes worth knowing: `/alerts`, `/alerts/<id>`, `/cases`, `/traffic`, `/entities/ip/10.20.0.45` (the demo's
  compromised workstation), `/hunt`, `/intel`, `/logs`, `/assets`, `/handover`, `/reports`, `/rules`,
  `/admin/users|settings|audit`.
- Need a new flow? Add a branch to `driver.mjs`; `login()`, `go(route)` and `shot(name)` are the building blocks.

### API directly (curl)

```bash
J=$(mktemp)
curl -s -c $J -X POST localhost:8000/api/auth/login -H 'content-type: application/json' \
  -d '{"username":"admin","password":"Agent-Run-Passw0rd!x"}'      # returns csrfToken
curl -s -b $J 'localhost:8000/api/alerts?limit=2'
```

GETs need only the cookie. Anything that changes data also needs the header `X-CSRF-Token: <csrfToken from login>`.
`/api/health` needs no auth.

## Run (human path)

Same as `run.sh up`, then open http://localhost:5173. The README's version (`uvicorn` + `python -m mysoc.sensor` + `npm run dev`
in three terminals from `backend/`) uses `backend/.env` and the real dev DB, with MFA turned on.

## Test

```bash
cd backend && .venv/bin/pytest -q && .venv/bin/ruff check mysoc tests     # 49 passed, ~4 s
cd frontend && npx tsc -b && npx eslint src                                # 0 errors, 7 react-refresh warnings (pre-existing)
```

## Gotchas

- **Never `waitForLoadState('networkidle')`.** The console keeps a server-sent events stream (`Live` badge) open,
  so networkidle always waits out the full 30 s timeout. The driver waits for `main h1` and for loading placeholders
  (`.skeleton` / `aria-busy`) to clear instead. That fix took a page from 31 s to about 1.5 s.
- **Alert rows aren't links.** They're `<tr class="clickable" onClick=navigate>`, so `a[href^="/alerts/"]` finds nothing.
  Click a non-checkbox cell: the checkbox `<td>` calls `stopPropagation`.
- **Two 401s on every page load before sign-in** (`GET /api/auth/me`) are normal. The driver only records console errors
  after sign-in.
- **Settings priority:** real env vars override `backend/.env` (pydantic-settings), which is how `run.sh` points everything
  at the throwaway DB without editing `.env`. The API and the sensor must get **the same** `MYSOC_DATABASE_URL`. If they
  don't, the UI shows no traffic.
- The bootstrap admin is created only when the DB has **no users**. Changing `MYSOC_AGENT_PASSWORD` after the first `up`
  does nothing; run `run.sh down --wipe` first.
- On first start the sensor backfills 24 h of demo history (about 2 s, ~50k flows), and the intrusion story replays every
  ~40 min, so alert counts climb while it runs (80 → 220+ within ~45 min). Don't assert exact counts.
- `MYSOC_DEV_KEY_FILE` is pointed into the state dir so secrets saved during a run don't use the dev vault key
  `backend/.mysoc-dev-vault.key`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `port 8000 already in use` from `run.sh up` | A dev server is already running (yours or a stale run). `run.sh down`, or `lsof -iTCP:8000 -sTCP:LISTEN` and stop it. |
| Driver `TimeoutError` waiting for `link "Overview"` | Sign-in failed: wrong password for an existing DB (see the bootstrap gotcha) → `run.sh down --wipe && run.sh up`. |
| Every driver page takes ~30 s | Something reintroduced `networkidle` (see Gotchas). |
