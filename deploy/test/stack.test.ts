// Template tests: the properties the deployment relies on. Run: npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { App } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { DefaultStackSynthesizer } from 'aws-cdk-lib';
import { KiroGatewayStack } from '../lib/gateway-stack';

function synth(vpcMode: 'new' | 'existing', source: 'git' | 'asset' = 'git') {
  const app = new App();
  const stack = new KiroGatewayStack(app, 'T', {
    vpcMode, source, analyticsReporting: false,
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: source === 'asset' }),
  });
  return Template.fromStack(stack);
}
const templates = { new: synth('new'), existing: synth('existing') };

for (const [mode, t] of Object.entries(templates)) {
  test(`${mode} VPC: plain CloudFormation (no Lambda, no assets, no bootstrap rule)`, () => {
    t.resourceCountIs('AWS::Lambda::Function', 0);
    const json = t.toJSON();
    assert.equal(json.Rules?.CheckBootstrapVersion, undefined);
    assert.equal(json.Parameters?.BootstrapVersion, undefined);
    assert.doesNotMatch(JSON.stringify(json), /cdk-hnb659fds|AWS::CDK::Metadata/);
  });

  test(`${mode} VPC: no public IP, account id or open ingress baked in`, () => {
    const s = JSON.stringify(t.toJSON());
    assert.doesNotMatch(s, /\b\d{12}\b/, 'account id');
    for (const sg of Object.values(t.findResources('AWS::EC2::SecurityGroup'))) {
      for (const rule of sg.Properties.SecurityGroupIngress ?? []) assert.notEqual(rule.CidrIp, '0.0.0.0/0');
    }
    assert.ok(t.toJSON().Rules?.NotOpenToTheWorld, 'rule refusing 0.0.0.0/0');
  });

  test(`${mode} VPC: instance hardening (IMDSv2, encrypted disks, no SSH, private subnet)`, () => {
    t.hasResourceProperties('AWS::EC2::LaunchTemplate', {
      LaunchTemplateData: Match.objectLike({
        MetadataOptions: { HttpTokens: 'required', HttpPutResponseHopLimit: 2 },
        BlockDeviceMappings: [Match.objectLike({ Ebs: Match.objectLike({ Encrypted: true }) })],
      }),
    });
    assert.equal(t.toJSON().Resources.LaunchTemplate04EC5460?.Properties.LaunchTemplateData.KeyName, undefined);
    t.hasResourceProperties('AWS::EC2::Volume', { Encrypted: true, VolumeType: 'gp3' });
    t.hasResource('AWS::EC2::Volume', { DeletionPolicy: 'Snapshot' });
    // only the two load balancers may reach the instance
    const ingress = Object.values(t.findResources('AWS::EC2::SecurityGroupIngress'));
    const fromSg = ingress.filter((r) => r.Properties.SourceSecurityGroupId);
    assert.equal(fromSg.length, 2, 'instance: ingress from its two load balancer SGs only');

  });

  test(`${mode} VPC: single gateway, replaced in place, deploy waits for the bootstrap`, () => {
    t.hasResource('AWS::AutoScaling::AutoScalingGroup', {
      Properties: Match.objectLike({ MinSize: '1', MaxSize: '1', HealthCheckType: 'ELB' }),
      CreationPolicy: { ResourceSignal: Match.objectLike({ Count: 1 }) },
      UpdatePolicy: { AutoScalingRollingUpdate: Match.objectLike({ MinInstancesInService: 0, WaitOnResourceSignals: true }) },
    });
    t.hasResourceProperties('AWS::DLM::LifecyclePolicy', { State: 'ENABLED' });
  });

  test(`${mode} VPC: guardrail is input-only PII + exfiltration topic, role may only apply it`, () => {
    t.hasResourceProperties('AWS::Bedrock::Guardrail', {
      TopicPolicyConfig: Match.objectLike({ TopicsConfig: [Match.objectLike({ Name: 'Data exfiltration', Type: 'DENY' })] }),
      SensitiveInformationPolicyConfig: Match.objectLike({
        PiiEntitiesConfig: Match.arrayWith([Match.objectLike({ Type: 'EMAIL', OutputEnabled: false })]),
      }),
    });
    assert.equal(t.toJSON().Resources.Guardrail.Properties.ContentPolicyConfig, undefined, 'no prompt-attack filter');
    const actions = Object.values(t.findResources('AWS::IAM::Policy'))
      .flatMap((p) => p.Properties.PolicyDocument.Statement).flatMap((st) => [st.Action].flat());
    assert.ok(actions.includes('bedrock:ApplyGuardrail'));
    assert.ok(!actions.some((a: string) => /^bedrock:(\*|Invoke)/.test(a)), 'no model invocation rights');
    assert.ok(!actions.some((a: string) => a.endsWith(':*') || a === '*'), 'no wildcard actions');
  });

  test(`${mode} VPC: portal only via CloudFront + WAF -> internal ALB that needs the secret origin header`, () => {
    // the portal ALB accepts only CloudFront's origin-facing prefix list
    const sgs = t.findResources('AWS::EC2::SecurityGroup');
    const albSgId = Object.keys(sgs).find((k) => /portal load balancer/.test(sgs[k].Properties.GroupDescription))!;
    assert.equal(sgs[albSgId].Properties.SecurityGroupIngress, undefined, 'no inline (CIDR) ingress');
    const albIngress = Object.values(t.findResources('AWS::EC2::SecurityGroupIngress'))
      .filter((r) => JSON.stringify(r.Properties.GroupId).includes(albSgId));
    assert.equal(albIngress.length, 1);
    assert.equal(albIngress[0].Properties.FromPort, 80);
    assert.match(JSON.stringify(albIngress[0].Properties.SourcePrefixListId), /CloudFrontOriginFacing/);
    // no internet-facing load balancer at all
    for (const lb of Object.values(t.findResources('AWS::ElasticLoadBalancingV2::LoadBalancer'))) {
      assert.equal(lb.Properties.Scheme, 'internal');
    }
    t.hasResourceProperties('AWS::CloudFront::VpcOrigin', Match.objectLike({
      VpcOriginEndpointConfig: Match.objectLike({ OriginProtocolPolicy: 'http-only', HTTPPort: 80 }),
    }));
    const dist = Object.values(t.findResources('AWS::CloudFront::Distribution'))[0].Properties.DistributionConfig;
    assert.ok(dist.WebACLId, 'web ACL attached');
    assert.equal(dist.DefaultCacheBehavior.ViewerProtocolPolicy, 'redirect-to-https');
    const hdr = dist.Origins[0].OriginCustomHeaders.find((h: { HeaderName: string }) => h.HeaderName === 'X-Kgw-Origin-Verify');
    assert.match(JSON.stringify(hdr.HeaderValue), /resolve:secretsmanager/, 'origin secret is a dynamic reference, not a literal');
    // the ALB: default 403, forward only with the header
    t.hasResourceProperties('AWS::ElasticLoadBalancingV2::Listener', Match.objectLike({
      Port: 80, DefaultActions: [Match.objectLike({ Type: 'fixed-response', FixedResponseConfig: Match.objectLike({ StatusCode: '403' }) })],
    }));
    t.hasResourceProperties('AWS::ElasticLoadBalancingV2::ListenerRule', Match.objectLike({
      Conditions: [Match.objectLike({ Field: 'http-header', HttpHeaderConfig: Match.objectLike({ HttpHeaderName: 'X-Kgw-Origin-Verify' }) })],
    }));
    t.hasResourceProperties('AWS::WAFv2::WebACL', Match.objectLike({
      Scope: 'CLOUDFRONT',
      Rules: Match.arrayWith([Match.objectLike({ Name: 'login-rate-limit' }), Match.objectLike({ Name: 'AWSManagedRulesCommonRuleSet' })]),
    }));
    assert.equal(t.toJSON().Parameters.PortalAllowedCidr, undefined, 'no portal IP allow list');
  });
}

test('existing VPC: network comes from parameters', () => {
  const p = templates.existing.toJSON().Parameters;
  for (const k of ['VpcId', 'AvailabilityZone', 'PrivateSubnetId', 'PrivateSubnet2Id']) assert.ok(p[k], k);
  assert.equal(p.PublicSubnetId, undefined, 'no public subnet needed');
  templates.existing.resourceCountIs('AWS::EC2::VPC', 0);
});

test('asset mode: the uploaded source excludes secrets and state', () => {
  const t = synth('new', 'asset');
  const ud = JSON.stringify(t.toJSON().Resources.LaunchTemplate04EC5460.Properties.LaunchTemplateData.UserData);
  assert.match(ud, /KGW_SOURCE_S3=/);
  assert.doesNotMatch(ud, /KGW_SOURCE_REPO=/);
});
