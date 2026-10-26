// Drive the mySOC console in headless Chromium. Signs in through the real
// login form every run (sessions are HttpOnly cookies; nothing to reuse).
//
//   node driver.mjs shot [route ...]   screenshot each route (default: /)
//   node driver.mjs triage             open the alert queue, open the top alert, take it
//   node driver.mjs text <route>       print the page's visible text
//   node driver.mjs eval <route> <js>  evaluate JS on the page, print JSON result
//
// Screenshots go to $MYSOC_SHOTS (default $TMPDIR/mysoc-run/shots).
import { chromium } from 'playwright'
import { mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

const BASE = process.env.MYSOC_URL ?? 'http://localhost:5173'
const USER = process.env.MYSOC_AGENT_USER ?? 'admin'
const PASS = process.env.MYSOC_AGENT_PASSWORD ?? 'Agent-Run-Passw0rd!x'
const SHOTS = process.env.MYSOC_SHOTS ?? join(process.env.TMPDIR ?? tmpdir(), 'mysoc-run', 'shots')
mkdirSync(SHOTS, { recursive: true })

const [cmd = 'shot', ...args] = process.argv.slice(2)
const browser = await chromium.launch()
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } })
const errors = []
// MYSOC_THEME=dark|light pins the console theme (it otherwise follows the OS, which is light headless).
if (process.env.MYSOC_THEME) await page.addInitScript((t) => localStorage.setItem('mysoc-theme', t), process.env.MYSOC_THEME)

async function login() {
  await page.goto(BASE)
  await page.locator('input[autocomplete="username"]').fill(USER)
  await page.locator('input[autocomplete="current-password"]').fill(PASS)
  await page.locator('button.btn.primary').click()
  // The sidebar only renders once fully signed in (not on MFA / password-change screens).
  await page.getByRole('link', { name: 'Overview' }).waitFor({ timeout: 15000 })
  // Listen only after sign-in: the pre-login /api/auth/me 401s are expected.
  page.on('pageerror', (e) => errors.push(e.message))
  page.on('console', (m) => m.type() === 'error' && errors.push(m.text()))
}

async function go(route) {
  await page.goto(BASE + route)
  // Never wait for 'networkidle': the live-updates SSE stream keeps a request
  // open forever, so it always burns the full 30 s timeout.
  await page.locator('main h1').first().waitFor({ timeout: 15000 })
  await page.waitForFunction(() => !document.querySelector('main .skeleton, main [aria-busy="true"]'), null, { timeout: 10000 }).catch(() => {})
  await page.waitForTimeout(1000) // queries resolve + charts animate in
}

async function shot(name) {
  const file = join(SHOTS, `${name.replace(/[^a-z0-9]+/gi, '_').replace(/^_|_$/g, '') || 'overview'}.png`)
  await page.screenshot({ path: file, fullPage: true })
  console.log('screenshot:', file)
}

try {
  await login()
  if (cmd === 'shot') {
    for (const r of args.length ? args : ['/']) { await go(r); await shot(r) }
  } else if (cmd === 'triage') {
    await go('/alerts')
    await shot('alerts')
    // Rows are <tr onClick=navigate>, not links. Pick the first still-New alert.
    const row = page.locator('tbody tr.clickable', { hasText: 'New' }).first()
    await row.waitFor({ timeout: 15000 })
    await row.locator('td').nth(2).click() // not the checkbox cell, which stops propagation
    await page.waitForURL(/\/alerts\/\d+$/)
    await page.waitForTimeout(800)
    console.log('opened', new URL(page.url()).pathname, '-', await page.locator('h1').first().innerText().catch(() => '?'))
    const take = page.getByRole('button', { name: 'Take it' })
    if (await take.count()) {
      await take.click()
      await take.waitFor({ state: 'detached', timeout: 5000 }) // button disappears once assigned to me
      console.log('took alert (status: In progress, assignee: me)')
    }
    await shot('alert_detail')
  } else if (cmd === 'search') {
    // Type into the top-bar search, screenshot the results panel, then open the first hit.
    await go('/')
    await page.keyboard.press('/')
    await page.keyboard.type(args[0] ?? '10.20', { delay: 40 })
    await page.waitForTimeout(400) // input is debounced 180 ms before the API calls start
    await page.locator('.search-hit').first().waitFor({ timeout: 10000 })
    await page.waitForFunction(() => !document.querySelector('.search-note')?.textContent?.startsWith('Searching'), null, { timeout: 10000 }).catch(() => {})
    console.log((await page.locator('#search-results').innerText()).split('\n').filter(Boolean).slice(0, 20).join('\n'))
    await page.screenshot({ path: join(SHOTS, 'search.png') })
    console.log('screenshot:', join(SHOTS, 'search.png'))
    await page.keyboard.press('Enter')
    await page.waitForTimeout(800)
    console.log('Enter ->', new URL(page.url()).pathname + new URL(page.url()).search)
  } else if (cmd === 'text') {
    await go(args[0] ?? '/')
    console.log(await page.locator('main').innerText())
  } else if (cmd === 'eval') {
    await go(args[0] ?? '/')
    console.log(JSON.stringify(await page.evaluate(args[1] ?? 'document.title'), null, 2))
  } else {
    throw new Error(`unknown command: ${cmd}`)
  }
  if (errors.length) console.log('page errors:\n  ' + errors.join('\n  '))
} finally {
  await browser.close()
}
