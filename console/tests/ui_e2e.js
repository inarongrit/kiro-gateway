const { chromium } = require('playwright'); const fs = require('fs');
const out = process.env.OUT || process.env.TMPDIR || '/tmp', pw = fs.readFileSync(process.env.PWFILE || 'pki/console-initial-password', 'utf8').trim(), step = process.argv[2];
(async () => {
  const b = await chromium.launch(); const ctx = await b.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1360, height: 900 } });
  const p = await ctx.newPage(); const errs = []; p.on('pageerror', e => errs.push(String(e)));
  await p.goto('' + (process.env.CONSOLE_URL || 'https://127.0.0.1:9180') + '/'); await p.fill('input[name=username]', 'admin'); await p.fill('input[name=password]', pw);
  await p.click('#loginForm button[type=submit]'); await p.waitForSelector('#app:not(.hidden)'); await p.waitForTimeout(800);
  if (step === 'add') {
    await p.click('#addRule'); await p.fill('#ruleForm input[name=label]', 'E2E demo secret');
    await p.fill('#ruleForm input[name=description]', 'Added by the Stage 5 end-to-end test');
    await p.fill('#ruleForm input[name=pattern]', 'E2E-SECRET-[0-9]{4}'); await p.waitForTimeout(700);
    await p.screenshot({ path: `${out}/e2e-1-dialog.png` });
    await p.click('#ruleForm button[type=submit]'); await p.waitForSelector('#savebar:not(.hidden)');
    await p.screenshot({ path: `${out}/e2e-2-unsaved.png` });
  } else {
    await p.locator('.rule', { hasText: 'E2E demo secret' }).getByRole('button', { name: 'Edit' }).click();
    p.once('dialog', d => d.accept()); await p.click('#delRule'); await p.waitForSelector('#savebar:not(.hidden)');
  }
  await p.click('#save'); await p.waitForSelector('#toast:not(.hidden)'); const t = await p.textContent('#toast');
  console.log(`${step} toast:`, t); await p.screenshot({ path: `${out}/e2e-${step}-saved.png` });
  if (step === 'add') {
    await p.fill('#tText', 'deploy with E2E-SECRET-1234 please'); await p.click('#tBtn'); await p.waitForSelector('#tRes:not(.hidden)');
    console.log('tester:', (await p.textContent('#tRes')).trim());
  }
  console.log('page errors:', JSON.stringify(errs)); await b.close();
})().catch(e => { console.error(e); process.exit(1); });
