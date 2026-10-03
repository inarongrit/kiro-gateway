// Copy the synthesized (git-mode) templates to dist/ as compact JSON, ready to upload to S3 for a
// CloudFormation "Launch Stack" link. Run via: npm run template [-- -c repoUrl=... -c repoRef=v1.0.0]
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';

mkdirSync('dist', { recursive: true });
for (const [stack, file] of [['KiroGateway', 'kiro-gateway.template.json'],
  ['KiroGatewayExistingVpc', 'kiro-gateway-existing-vpc.template.json']]) {
  const t = JSON.parse(readFileSync(`cdk.out/${stack}.template.json`, 'utf8'));
  if (Object.keys(t.Parameters ?? {}).includes('BootstrapVersion')) {
    throw new Error(`${stack}: synthesized in asset mode; run without -c source=asset`);
  }
  const out = JSON.stringify(t);
  writeFileSync(`dist/${file}`, out + '\n');
  console.log(`dist/${file} (${out.length} bytes)`);
}
