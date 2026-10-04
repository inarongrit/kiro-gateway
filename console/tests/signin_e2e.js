// Run: B=https://127.0.0.1:9180 PW=$(cat pki/console-initial-password) NODE_PATH=$(npm root -g) node console/tests/signin_e2e.js
// Sign-in page checks: unauthenticated / and /ui/ show the form; signing in lands on the portal;
// a signed-in visit to / goes straight on; ?next=grafana lands on Grafana; ?next=<url> cannot redirect off-site.
const { chromium } = require('playwright');
const B = process.env.B, PW = process.env.PW;
(async () => {
  const b = await chromium.launch();
  const ctx = await b.newContext({ ignoreHTTPSErrors: true });
  const p = await ctx.newPage(); const errs = []; p.on('pageerror', (e) => errs.push(String(e)));
  let fails = 0; const ok = (c, m) => { console.log((c ? 'PASS  ' : 'FAIL  ') + m); if (!c) fails++; };
  await p.goto(B + '/ui/'); await p.waitForTimeout(1500);
  ok(await p.locator('#loginForm').isVisible() && /\/\?next=ui/.test(p.url()), `unauthenticated /ui/ -> sign-in form (${new URL(p.url()).pathname + new URL(p.url()).search})`);
  await p.fill('input[name=password]', 'wrong-password-zz'); await p.fill('input[name=username]', 'admin');
  await p.click('button[type=submit]'); await p.waitForTimeout(1200);
  ok(/wrong username or password/i.test(await p.locator('#loginErr').innerText()), 'wrong password shows the error');
  await p.fill('input[name=password]', PW); await p.click('button[type=submit]');
  await p.waitForURL('**/ui/**', { timeout: 15000 }); await p.waitForTimeout(2500);
  ok(/\/ui\//.test(p.url()) && /Overview/.test(await p.locator('body').innerText()), 'sign-in lands on the portal overview');
  await p.goto(B + '/'); await p.waitForURL('**/ui/**', { timeout: 10000 });
  ok(/\/ui\/$/.test(p.url()), 'signed-in visit to / goes straight to the portal');
  await p.goto(B + '/?next=grafana'); await p.waitForURL('**/grafana/**', { timeout: 10000 });
  ok(/\/grafana\//.test(p.url()), '?next=grafana lands on Grafana');
  await p.goto(B + '/?next=https://evil.example/'); await p.waitForTimeout(2000);
  ok(new URL(p.url()).host === new URL(B).host, `?next=<external url> stays on the gateway (${new URL(p.url()).pathname})`);
  ok(errs.length === 0, `no page errors ${errs.join('; ')}`);
  await b.close(); console.log(fails ? `${fails} FAILED` : 'ALL PASS'); process.exit(fails ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
