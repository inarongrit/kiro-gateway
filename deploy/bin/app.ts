#!/usr/bin/env node
/**
 * Kiro Gateway CDK app. Two stacks, same gateway, plus the portal WAF for other regions:
 *   KiroGateway             creates a VPC (2 AZs, 1 NAT gateway)
 *   KiroGatewayExistingVpc  uses a VPC + subnets you pass as parameters
 *   KiroGatewayPortalWaf    the portal web ACL alone, deployed in us-east-1 for a gateway elsewhere
 *
 * Context (-c key=value):
 *   source=git|asset  git (default): the instance clones repoUrl@repoRef; the template has no CDK
 *                     assets, so it also works as a plain CloudFormation template (Launch Stack).
 *                     asset: upload this checkout instead (needs `cdk bootstrap`; for development).
 *   repoUrl, repoRef  defaults for the SourceRepoUrl / SourceRef parameters (git mode)
 */
import { App, DefaultStackSynthesizer, Validations } from 'aws-cdk-lib';
import { AwsSolutionsChecks } from 'cdk-nag';
import { KiroGatewayStack } from '../lib/gateway-stack';
import { KiroGatewayPortalWafStack } from '../lib/portal-waf';

const app = new App();
const source = app.node.tryGetContext('source') === 'asset' ? 'asset' : 'git';
const common = {
  source,
  repoUrl: app.node.tryGetContext('repoUrl') || undefined,
  repoRef: app.node.tryGetContext('repoRef') || undefined,
  analyticsReporting: false,
  // git mode: no bootstrap version rule, so the template deploys in accounts without `cdk bootstrap`.
  synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: source === 'asset' }),
} as const;

new KiroGatewayStack(app, 'KiroGateway', { ...common, vpcMode: 'new' });
new KiroGatewayStack(app, 'KiroGatewayExistingVpc', { ...common, vpcMode: 'existing' });
new KiroGatewayPortalWafStack(app, 'KiroGatewayPortalWaf', { analyticsReporting: false, synthesizer: common.synthesizer });
Validations.of(app).addPlugins(new AwsSolutionsChecks(app, { verbose: true }));
