import { Aws, CfnOutput, CfnRule, Fn, Stack, StackProps } from 'aws-cdk-lib';
import * as wafv2 from 'aws-cdk-lib/aws-wafv2';
import { Construct } from 'constructs';

/**
 * AWS WAF for the portal (CLOUDFRONT scope, so it can only be created in us-east-1).
 * Rate limits per viewer IP, AWS IP reputation, known bad inputs and the common rule set. The
 * common rules' BODY/size checks run in COUNT mode: prompts, rule patterns and Grafana queries
 * legitimately contain code, regexes and long bodies, and inspecting them is the gateway's job.
 */
export function portalWebAcl(scope: Construct, id: string): wafv2.CfnWebACL {
  const vis = (name: string) => ({ cloudWatchMetricsEnabled: true, metricName: name, sampledRequestsEnabled: true });
  const managed = (name: string, priority: number, countRules: string[] = []) => ({
    name, priority, overrideAction: { none: {} }, visibilityConfig: vis(name),
    statement: { managedRuleGroupStatement: {
      vendorName: 'AWS', name, ruleActionOverrides: countRules.map((r) => ({ name: r, actionToUse: { count: {} } })),
    } },
  });
  return new wafv2.CfnWebACL(scope, id, {
    scope: 'CLOUDFRONT', defaultAction: { allow: {} }, visibilityConfig: vis('kiro-gateway-portal'),
    description: 'Kiro Gateway portal: rate limits + AWS managed rules',
    rules: [
      { name: 'login-rate-limit', priority: 0, action: { block: {} }, visibilityConfig: vis('login-rate-limit'),
        statement: { rateBasedStatement: { limit: 20, evaluationWindowSec: 300, aggregateKeyType: 'IP',
          scopeDownStatement: { byteMatchStatement: { fieldToMatch: { uriPath: {} }, positionalConstraint: 'EXACTLY',
            searchString: '/api/login', textTransformations: [{ priority: 0, type: 'NONE' }] } } } } },
      { name: 'rate-limit', priority: 1, action: { block: {} }, visibilityConfig: vis('rate-limit'),
        statement: { rateBasedStatement: { limit: 3000, evaluationWindowSec: 300, aggregateKeyType: 'IP' } } },
      managed('AWSManagedRulesAmazonIpReputationList', 2),
      managed('AWSManagedRulesKnownBadInputsRuleSet', 3),
      managed('AWSManagedRulesCommonRuleSet', 4, ['SizeRestrictions_BODY', 'SizeRestrictions_QUERYSTRING',
        'CrossSiteScripting_BODY', 'GenericLFI_BODY', 'GenericRFI_BODY', 'EC2MetaDataSSRF_BODY']),
    ],
  });
}

/**
 * The portal web ACL on its own, for gateways outside us-east-1: deploy this in us-east-1, then
 * pass its WebAclArn output as CloudFrontWebAclArn to the gateway stack in your region.
 */
export class KiroGatewayPortalWafStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);
    this.templateOptions.description = 'Kiro Gateway: AWS WAF web ACL for the portal (CloudFront scope, us-east-1), '
      + 'for gateway stacks deployed in other regions.';
    new CfnRule(this, 'InUsEast1', {
      assertions: [{
        assert: Fn.conditionEquals(Aws.REGION, 'us-east-1'),
        assertDescription: 'Deploy this stack in us-east-1 (CloudFront only accepts web ACLs from there).',
      }],
    });
    const acl = portalWebAcl(this, 'PortalWebAcl');
    new CfnOutput(this, 'WebAclArn', {
      value: acl.attrArn, description: 'Pass as CloudFrontWebAclArn to the Kiro Gateway stack in your region',
    });
  }
}
