// Final end-to-end run through the portal, recorded: add a rule -> real kiro-cli blocked ->
// Run: NODE_PATH=$(npm root -g) OUT=$(mktemp -d) node console/tests/portal_e2e.js   (adds + removes a rule, sends real kiro-cli prompts)
// visible in Activity/Overview -> trace + Grafana + Gateway pages -> remove rule -> kiro-cli allowed.
const { chromium } = require('playwright'); const fs = require('fs'); const { spawnSync } = require('child_process');
const GW = require('path').resolve(__dirname, '../..'), B = 'https://127.0.0.1:9180', OUT = process.env.OUT;
const TAG = 'FINAL-E2E-' + String(1000 + Math.floor(Math.random() * 8999));
const results = []; const ok = (c, m) => { results.push([!!c, m]); console.log((c ? 'PASS  ' : 'FAIL  ') + m); };
const kiro = (prompt) => {
  const r = spawnSync(`${GW}/scripts/kiro-via-gateway`, ['run', 'kiro-cli', 'chat', '--no-interactive', '--trust-tools=', prompt],
    { cwd: OUT, timeout: 150000, encoding: 'utf8' });
  return ((r.stdout || '') + (r.stderr || '')).replace(/[^\x20-\x7e\n]/g, '').trim().split('\n').pop() || '';
};
(async () => {
  const pw = fs.readFileSync(`${GW}/pki/console-initial-password`, 'utf8').trim();
  const b = await chromium.launch();
  const ctx = await b.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 }, recordVideo: { dir: OUT, size: { width: 1440, height: 900 } } });
  const p = await ctx.newPage(); const errs = [];
  p.on('pageerror', e => errs.push(String(e).slice(0, 160)));
  const shot = (n) => p.screenshot({ path: `${OUT}/e2e-${n}.png` });
  await p.goto(B + '/ui/'); await p.fill('input[name=username]', 'admin'); await p.fill('input[name=password]', pw);
  await p.click('#loginForm button[type=submit]'); await p.waitForURL('**/ui/**'); await p.waitForTimeout(3000);
  ok(/\/ui\/overview/.test(p.url()), 'sign-in lands on the portal Overview'); await shot('01-overview');

  // 1. add a rule through the portal (draft -> review -> apply)
  await p.goto(B + '/ui/guardrails/rules'); await p.waitForTimeout(2000);
  await p.getByRole('button', { name: /add rule/i }).click(); await p.waitForTimeout(400);
  const dr = p.locator('.mantine-Drawer-content');
  await dr.getByLabel(/^name/i).fill('Final E2E secret');
  await dr.getByLabel(/^pattern/i).fill('FINAL-E2E-[0-9]{4}'); await p.waitForTimeout(1300);
  ok(await dr.locator('text=/Valid pattern/i').count() > 0, 'rule drawer: live PCRE check says the pattern is valid');
  await shot('02-rule-drawer');
  await dr.getByRole('button', { name: /save rule/i }).click(); await p.waitForTimeout(400);
  await p.getByRole('button', { name: /review/i }).click(); await p.waitForTimeout(600); await shot('03-review');
  await p.getByRole('button', { name: /apply to gateway/i }).click(); await p.waitForTimeout(7000);
  ok(await p.locator('text=final-e2e-secret').count() > 0, 'rule applied and listed on the Rules page');

  // 2. prompt tester sees it (layer 1)
  await p.goto(B + '/ui/guardrails/tester'); await p.waitForTimeout(1500);
  await p.locator('textarea').first().fill(`please store token ${TAG} in the config`);
  await p.getByRole('button', { name: /check prompt/i }).click(); await p.waitForTimeout(2500);
  ok(await p.locator('text=Would be blocked').count() > 0, 'prompt tester: would be blocked');
  const marks = await p.locator('mark').allTextContents();
  ok(marks.some(m => /^FI\*+\d\d$/.test(m)) && marks.includes(TAG), `tester shows masked preview + highlights the user's own text (${marks.join(' | ')})`);
  await shot('04-tester');

  // 3. real kiro-cli through the gateway
  const blocked = kiro(`Remember this deployment token ${TAG} for later`);
  ok(/Blocked by organization AI gateway policy.*Final E2E secret/.test(blocked), `kiro-cli blocked by the new rule: "${blocked.slice(-90)}"`);
  const clean = kiro('What is 17 + 25? Answer with just the number.');
  ok(/42/.test(clean), `kiro-cli clean prompt answered: "${clean.slice(-40)}"`);
  await p.waitForTimeout(6000);

  // 4. activity + overview show it, masked
  await p.goto(B + '/ui/guardrails/activity'); await p.waitForTimeout(2000);
  await p.getByPlaceholder(/search/i).first().fill('FINAL-E2E'); await p.waitForTimeout(3500);
  const row = p.locator('tbody tr').first(); const rowText = (await row.innerText()).replace(/\s+/g, ' ');
  ok(/Blocked/i.test(rowText) && /Final E2E secret/.test(rowText), `activity row: ${rowText.slice(0, 110)}`);
  ok(!rowText.includes(TAG) && /FI\*+\d\d/.test(rowText), 'activity shows the token masked, never in clear text');
  await row.click(); await p.waitForTimeout(1000); await shot('05-activity-drawer');
  const drawerText = await p.locator('.mantine-Drawer-content').innerText();
  ok(!drawerText.includes(TAG), 'activity details drawer has no clear-text token');
  await p.keyboard.press('Escape');
  await p.goto(B + '/ui/overview'); await p.waitForTimeout(3500);
  ok(await p.locator('text=Final E2E secret').count() > 0, 'Overview (blocks by rule / live activity) shows the new rule');
  await shot('06-overview-after');

  // 5. observability, a trace, Grafana, Gateway pages
  await p.goto(B + '/ui/observability/traffic'); await p.waitForTimeout(3500);
  ok(await p.locator('.recharts-surface').count() >= 3, 'Traffic page renders its charts'); await shot('07-traffic');
  await p.goto(B + '/ui/observability/traces'); await p.waitForTimeout(3500);
  await p.locator('tbody tr').first().click(); await p.waitForTimeout(2500);
  ok(await p.locator('text=Waterfall').count() > 0, 'trace drawer shows the span waterfall'); await shot('08-trace');
  await p.keyboard.press('Escape');
  await p.goto(B + '/grafana/d/kiro-gateway-guardrails'); await p.waitForTimeout(6000);
  ok(/Guardrails/.test(await p.title()) && await p.locator('text=/Sign in|Log in/i').count() === 0, `Grafana dashboard opens with the same sign-in (title "${await p.title()}")`);
  await shot('09-grafana');
  await p.goto(B + '/ui/routes'); await p.waitForTimeout(2500);
  ok(await p.locator('tbody tr').count() >= 3 && await p.locator('text=/status code 401|failed to check token/').count() === 0, 'Gateway > Routes loads without a separate admin key');
  await shot('10-routes');

  // 6. remove the rule through the portal
  await p.goto(B + '/ui/guardrails/rules'); await p.waitForTimeout(2000);
  await p.locator('tr', { hasText: 'final-e2e-secret' }).getByRole('button').last().click(); await p.waitForTimeout(300);
  await p.getByRole('menuitem', { name: /delete/i }).click(); await p.waitForTimeout(300);
  const confirm = p.getByRole('button', { name: /^delete/i }); if (await confirm.count()) await confirm.last().click();
  await p.getByRole('button', { name: /review/i }).click(); await p.waitForTimeout(500);
  await p.getByRole('button', { name: /apply to gateway/i }).click(); await p.waitForTimeout(7000);
  ok(await p.locator('tbody >> text=final-e2e-secret').count() === 0, 'rule removed through the portal');
  // the exact sentence that was blocked earlier must now get an answer
  const after = kiro(`Remember this deployment token ${TAG} for later`);
  ok(!/Blocked by organization/.test(after) && after.length > 0, `kiro-cli: the same sentence is answered after removal: "${after.slice(-70)}"`);

  ok(errs.length === 0, `no page errors (${JSON.stringify(errs)})`);
  const vpath = await p.video().path(); await ctx.close(); await b.close();
  fs.renameSync(vpath, `${OUT}/e2e-recording.webm`);
  const failed = results.filter(r => !r[0]).length;
  console.log(`\n${results.length - failed}/${results.length} passed  tag=${TAG}`); process.exit(failed ? 1 : 0);
})().catch(e => { console.error(String(e).slice(0, 500)); process.exit(1); });
