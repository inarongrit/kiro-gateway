const { chromium } = require('playwright'); const fs = require('fs');
// Run: cd $(mktemp -d) && npm i -E axe-core@4.13.0 && NODE_PATH=$(npm root -g):$PWD/node_modules PWFILE=<repo>/pki/console-initial-password node <repo>/console/tests/portal_sweep.js
const AXE = fs.readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');
const PORTAL = ['overview', 'guardrails/rules', 'guardrails/activity', 'guardrails/tester',
  'observability/traffic', 'observability/latency', 'observability/usage', 'observability/traces'];
const GATEWAY = ['services', 'routes', 'stream_routes', 'upstreams', 'consumers', 'consumer_groups', 'ssls', 'global_rules', 'plugin_metadata', 'plugin_configs', 'secrets', 'protos'];
(async () => {
  const pw = fs.readFileSync(process.env.PWFILE, 'utf8').trim(); const b = await chromium.launch(); const rows = [];
  for (const [tag, vp, scheme] of [['dark', { width: 1440, height: 1000 }, 'dark'], ['light', { width: 1440, height: 1000 }, 'light'], ['mobile', { width: 390, height: 844 }, 'dark']]) {
    const ctx = await b.newContext({ ignoreHTTPSErrors: true, viewport: vp, colorScheme: scheme }); const p = await ctx.newPage();
    const errs = []; p.on('pageerror', e => errs.push(String(e).slice(0, 120)));
    await p.goto('https://127.0.0.1:9180/ui/'); await p.fill('input[name=username]', 'admin'); await p.fill('input[name=password]', pw);
    await p.click('#loginForm button[type=submit]'); await p.waitForURL('**/ui/**');
    await p.evaluate(s => localStorage.setItem('mantine-color-scheme-value', s), scheme);
    for (const r of [...PORTAL, ...GATEWAY]) {
      const before = errs.length;
      await p.goto('https://127.0.0.1:9180/ui/' + r); await p.waitForTimeout(r.includes('/') || r === 'overview' ? 3000 : 1800);
      const broken = await p.locator('text=/Something went wrong|status code 401|failed to check token/').count();
      const overflow = await p.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      let axe = '-';
      if (PORTAL.includes(r) && tag !== 'mobile') {
        await p.addScriptTag({ content: AXE });
        axe = (await p.evaluate(async () => (await axe.run(document, { runOnly: ['wcag2a', 'wcag2aa'] })).violations.map(v => `${v.id}(${v.nodes.length})`))).join(' ') || '0';
      }
      if (PORTAL.includes(r) && tag === 'mobile') await p.screenshot({ path: `sweep-m-${r.replace('/', '-')}.png`, clip: { x: 0, y: 0, width: 390, height: 1200 }, fullPage: true });
      if (PORTAL.includes(r) && tag === 'light') await p.screenshot({ path: `sweep-l-${r.replace('/', '-')}.png` });
      rows.push({ tag, r, broken, overflow, axe, errs: errs.length - before });
    }
    await ctx.close();
  }
  await b.close();
  const bad = rows.filter(x => x.broken || x.overflow > 0 || x.errs || (x.axe !== '-' && x.axe !== '0'));
  for (const x of bad) console.log('ISSUE', JSON.stringify(x));
  const portalAxe = rows.filter(x => x.axe !== '-');
  console.log(`pages checked: ${rows.length} (${PORTAL.length + GATEWAY.length} pages x 3 modes); issues: ${bad.length}; axe-scanned: ${portalAxe.length}, clean: ${portalAxe.filter(x => x.axe === '0').length}`);
})().catch(e => { console.error(String(e).slice(0, 400)); process.exit(1); });
