import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import * as path from 'node:path';
import {
  Aws, CfnCondition, CfnDeletionPolicy, CfnMapping, CfnOutput, CfnParameter, CfnRule, Duration, Fn, RemovalPolicy,
  Stack, StackProps, Tags, Validations,
} from 'aws-cdk-lib';
import * as autoscaling from 'aws-cdk-lib/aws-autoscaling';
import * as bedrock from 'aws-cdk-lib/aws-bedrock';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cwActions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as dlm from 'aws-cdk-lib/aws-dlm';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as s3assets from 'aws-cdk-lib/aws-s3-assets';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import * as wafv2 from 'aws-cdk-lib/aws-wafv2';
import { Construct } from 'constructs';
import { GUARDRAIL } from './guardrail-policy';

export interface KiroGatewayStackProps extends StackProps {
  /** 'new': the stack creates a VPC. 'existing': VPC and subnets are template parameters. */
  readonly vpcMode: 'new' | 'existing';
  /**
   * Where the instance gets the gateway code. 'git': clone SourceRepoUrl@SourceRef (no CDK
   * assets, so the synthesized template works as a plain CloudFormation "Launch Stack").
   * 'asset': upload this checkout as a CDK asset (needs `cdk bootstrap`; for development).
   */
  readonly source: 'git' | 'asset';
  /** Default for the SourceRepoUrl parameter (git mode). */
  readonly repoUrl?: string;
  /** Default for the SourceRef parameter (git mode). */
  readonly repoRef?: string;
}

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const PORTAL_PORT = 9180;   // KGW_PORT on the host (console container port 9200)
const ORIGIN_HEADER = 'X-Kgw-Origin-Verify';   // secret header CloudFront adds; the ALB requires it
/** AWS-managed prefix list com.amazonaws.global.cloudfront.origin-facing, per supported region. */
const CLOUDFRONT_ORIGIN_FACING: Record<string, string> = {
  'us-east-1': 'pl-3b927c52', 'us-east-2': 'pl-b6a144df', 'us-west-2': 'pl-82a045eb',
  'eu-central-1': 'pl-a3a144ca', 'eu-west-1': 'pl-4fa04526', 'eu-west-3': 'pl-75b1541c',
  'ap-northeast-1': 'pl-58a04531', 'ap-south-1': 'pl-9aa247f3', 'ap-southeast-1': 'pl-31a34658',
  'ap-southeast-2': 'pl-b8a742d1',
};
const PROXY_PORT = 3128;
const CIDR_PATTERN = '^(\\d{1,3}\\.){3}\\d{1,3}/(\\d|[12]\\d|3[0-2])$';
const TAG_KEY = 'KiroGateway';

export class KiroGatewayStack extends Stack {
  constructor(scope: Construct, id: string, props: KiroGatewayStackProps) {
    super(scope, id, props);
    this.templateOptions.description =
      'Kiro Gateway: guardrails, audit and monitoring for Kiro (Squid + APISIX TLS interception, '
      + 'regex + Amazon Bedrock Guardrails, portal, Prometheus/Loki/Tempo/Grafana) on one EC2 instance.';

    // ---- parameters ----------------------------------------------------------------------------
    const webAclParam = new CfnParameter(this, 'CloudFrontWebAclArn', {
      default: '',
      description: 'Leave empty in us-east-1: the stack creates the AWS WAF web ACL for the portal. In other regions, '
        + 'pass the ARN of a CLOUDFRONT-scope web ACL created in us-east-1 (CloudFront only accepts those).',
      allowedPattern: '^$|^arn:aws[a-z-]*:wafv2:us-east-1:\\d{12}:global/webacl/\\S+$',
    });
    const proxyCidr = new CfnParameter(this, 'ProxyAllowedCidr', {
      description: 'IPv4 CIDR of the Kiro clients that may use the proxy (port 3128 on the internal load balancer).',
      allowedPattern: CIDR_PATTERN, constraintDescription: 'an IPv4 CIDR such as 10.0.0.0/8',
      ...(props.vpcMode === 'new' ? { default: '10.40.0.0/16' } : {}),
    });
    const instanceType = new CfnParameter(this, 'InstanceType', {
      description: 'Gateway instance type (x86_64). The first boot builds the images; 8 GiB of memory is the comfortable minimum.',
      default: 't3.large', allowedValues: ['t3.large', 't3.xlarge', 'm6i.large', 'm6i.xlarge', 'm7i.large', 'm7i.xlarge'],
    });
    const dataSize = new CfnParameter(this, 'DataVolumeSize', {
      type: 'Number', default: 50, minValue: 20, maxValue: 2000,
      description: 'Size in GiB of the encrypted data volume (rules, CA, audit log, metrics, logs, traces, images). Snapshotted daily.',
    });
    const snapshotDays = new CfnParameter(this, 'SnapshotRetentionDays', {
      type: 'Number', default: 7, minValue: 1, maxValue: 1000, description: 'How many daily data-volume snapshots to keep.',
    });
    const alarmEmail = new CfnParameter(this, 'AlarmEmail', {
      default: '', description: 'Optional e-mail address for health alarms (confirm the SNS subscription mail).',
      allowedPattern: '^$|^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$',
    });
    let repoUrl: CfnParameter | undefined;
    let repoRef: CfnParameter | undefined;
    if (props.source === 'git') {
      repoUrl = new CfnParameter(this, 'SourceRepoUrl', {
        description: 'HTTPS URL of the kiro-gateway git repository the instance deploys.',
        allowedPattern: '^https://\\S+$', ...(props.repoUrl ? { default: props.repoUrl } : {}),
      });
      repoRef = new CfnParameter(this, 'SourceRef', {
        description: 'Branch or tag to deploy (use a release tag in production).', default: props.repoRef ?? 'main',
        allowedPattern: '^[A-Za-z0-9._/-]+$',
      });
    }
    new CfnRule(this, 'NotOpenToTheWorld', {
      assertions: [{
        assert: Fn.conditionNot(Fn.conditionEquals(proxyCidr.valueAsString, '0.0.0.0/0')),
        assertDescription: 'ProxyAllowedCidr must not be 0.0.0.0/0: an open proxy can be abused by anyone who reaches it.',
      }],
    });

    // ---- network -------------------------------------------------------------------------------
    let vpc: ec2.IVpc;
    const groups: { label: string; parameters: string[] }[] = [];
    if (props.vpcMode === 'new') {
      const flowLogs = new logs.LogGroup(this, 'FlowLogs', { retention: logs.RetentionDays.ONE_MONTH, removalPolicy: RemovalPolicy.DESTROY });
      vpc = new ec2.Vpc(this, 'Vpc', {
        ipAddresses: ec2.IpAddresses.cidr('10.40.0.0/16'), maxAzs: 2, natGateways: 1,
        restrictDefaultSecurityGroup: false,   // the restricting custom resource needs a Lambda asset
        subnetConfiguration: [
          { name: 'public', subnetType: ec2.SubnetType.PUBLIC, cidrMask: 24 },
          { name: 'private', subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS, cidrMask: 22 },
        ],
        flowLogs: { rejected: { destination: ec2.FlowLogDestination.toCloudWatchLogs(flowLogs), trafficType: ec2.FlowLogTrafficType.REJECT } },
      });
    } else {
      const vpcId = new CfnParameter(this, 'VpcId', { type: 'AWS::EC2::VPC::Id', description: 'Existing VPC.' });
      const az = new CfnParameter(this, 'AvailabilityZone', {
        type: 'AWS::EC2::AvailabilityZone::Name', description: 'Availability Zone of PrivateSubnetId (the gateway instance and its data volume).',
      });
      const priv = new CfnParameter(this, 'PrivateSubnetId', {
        type: 'AWS::EC2::Subnet::Id', description: 'Private subnet with outbound internet (NAT) for the gateway instance and the internal load balancers.',
      });
      const priv2 = new CfnParameter(this, 'PrivateSubnet2Id', {
        type: 'AWS::EC2::Subnet::Id', description: 'Second private subnet, in another Availability Zone (load balancers span two).',
      });
      vpc = ec2.Vpc.fromVpcAttributes(this, 'Vpc', {
        vpcId: vpcId.valueAsString,
        // the second AZ is never read (only subnet IDs are used for the load balancers)
        availabilityZones: [az.valueAsString, Fn.select(1, Fn.getAzs())],
        privateSubnetIds: [priv.valueAsString, priv2.valueAsString],
      });
      groups.push({ label: 'Existing network', parameters: ['VpcId', 'AvailabilityZone', 'PrivateSubnetId', 'PrivateSubnet2Id'] });
      Validations.of(vpc).acknowledge({
        id: 'Construct-Annotations::@aws-cdk/aws-ec2:noSubnetRouteTableId',
        reason: 'Imported subnets: the stack never reads their route tables.',
      });
    }
    // One instance, one AZ: the data volume is zonal. The ASG replaces a failed instance in place.
    const gwSubnet = vpc.privateSubnets[0];

    // Portal path: viewer -HTTPS-> CloudFront (+ AWS WAF) -VPC origin-> internal ALB -HTTPS-> instance.
    // VPC-origin traffic arrives from CloudFront's origin-facing addresses (seen in flow logs), so the
    // ALB allows the AWS-managed prefix list for them, and forwards only requests that carry
    // CloudFront's secret origin header (anything else: 403).
    const cfPrefixLists = new CfnMapping(this, 'CloudFrontOriginFacing', {
      mapping: Object.fromEntries(Object.entries(CLOUDFRONT_ORIGIN_FACING).map(([r, id]) => [r, { id }])),
    });
    const portalLbSg = new ec2.SecurityGroup(this, 'PortalLbSg', {
      vpc, allowAllOutbound: false, description: 'Kiro Gateway portal load balancer (internal): from CloudFront only',
    });
    portalLbSg.addIngressRule(ec2.Peer.prefixList(cfPrefixLists.findInMap(Aws.REGION, 'id')), ec2.Port.tcp(80),
      'CloudFront origin-facing (VPC origin)');
    const proxyLbSg = new ec2.SecurityGroup(this, 'ProxyLbSg', {
      vpc, allowAllOutbound: false, description: 'Kiro Gateway proxy load balancer: port 3128 from ProxyAllowedCidr',
    });
    proxyLbSg.addIngressRule(ec2.Peer.ipv4(proxyCidr.valueAsString), ec2.Port.tcp(PROXY_PORT), 'Kiro clients');
    const instanceSg = new ec2.SecurityGroup(this, 'InstanceSg', {
      vpc, allowAllOutbound: true,   // Kiro service endpoints, container registries, AWS APIs
      description: 'Kiro Gateway instance: only from its two load balancers (no SSH; use Session Manager)',
    });
    instanceSg.addIngressRule(portalLbSg, ec2.Port.tcp(PORTAL_PORT), 'portal load balancer');
    instanceSg.addIngressRule(proxyLbSg, ec2.Port.tcp(PROXY_PORT), 'proxy load balancer');
    portalLbSg.addEgressRule(instanceSg, ec2.Port.tcp(PORTAL_PORT), 'to the gateway');
    proxyLbSg.addEgressRule(instanceSg, ec2.Port.tcp(PROXY_PORT), 'to the gateway');

    const portalLb = new elbv2.ApplicationLoadBalancer(this, 'PortalAlb', {
      vpc, internetFacing: false, vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      securityGroup: portalLbSg, dropInvalidHeaderFields: true, idleTimeout: Duration.seconds(120),
    });
    // The proxy load balancer passes TCP through with the client IP preserved, so Squid's own ACL
    // (ProxyAllowedCidr) applies too.
    const proxyLb = new elbv2.NetworkLoadBalancer(this, 'ProxyLb', {
      vpc, internetFacing: false, vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      securityGroups: [proxyLbSg], crossZoneEnabled: true,
    });

    // ---- Bedrock guardrail (layer 2) ------------------------------------------------------------
    // The STANDARD topic tier needs a cross-region guardrail profile (us. / eu. / apac.).
    const profileByRegion: Record<string, string> = {
      'us-east-1': 'us', 'us-east-2': 'us', 'us-west-2': 'us',
      'eu-central-1': 'eu', 'eu-west-1': 'eu', 'eu-west-3': 'eu',
      'ap-northeast-1': 'apac', 'ap-south-1': 'apac', 'ap-southeast-1': 'apac', 'ap-southeast-2': 'apac',
    };
    const profiles = new CfnMapping(this, 'GuardrailProfile', {
      mapping: Object.fromEntries(Object.entries(profileByRegion).map(([r, id]) => [r, { id }])),
    });
    new CfnRule(this, 'SupportedRegion', {
      assertions: [{
        assert: Fn.conditionContains(Object.keys(profileByRegion), Aws.REGION),
        assertDescription: `Supported regions: ${Object.keys(profileByRegion).join(', ')}.`,
      }],
    });
    const profileArn = `arn:${Aws.PARTITION}:bedrock:${Aws.REGION}:${Aws.ACCOUNT_ID}:guardrail-profile/`
      + `${profiles.findInMap(Aws.REGION, 'id')}.guardrail.v1:0`;
    const guardrail = new bedrock.CfnGuardrail(this, 'Guardrail', {
      name: `${Aws.STACK_NAME}-kiro`,
      description: 'Kiro Gateway layer 2: PII and data-exfiltration checks on Kiro prompts (input only).',
      blockedInputMessaging: GUARDRAIL.blockedMessage,
      blockedOutputsMessaging: GUARDRAIL.blockedMessage,
      crossRegionConfig: { guardrailProfileArn: profileArn },
      sensitiveInformationPolicyConfig: {
        piiEntitiesConfig: GUARDRAIL.piiEntities.map((type) => ({
          type, action: 'BLOCK', inputAction: 'BLOCK', inputEnabled: true, outputEnabled: false,
        })),
        regexesConfig: GUARDRAIL.regexes.map((r) => ({
          ...r, action: 'BLOCK', inputAction: 'BLOCK', inputEnabled: true, outputEnabled: false,
        })),
      },
      topicPolicyConfig: {
        topicsTierConfig: { tierName: 'STANDARD' },
        topicsConfig: GUARDRAIL.topics.map((t) => ({
          ...t, type: 'DENY', inputAction: 'BLOCK', inputEnabled: true, outputEnabled: false,
        })),
      },
    });
    // A new version is published whenever the policy above changes (the hash is in the description).
    const policyHash = createHash('sha256').update(JSON.stringify(GUARDRAIL)).digest('hex').slice(0, 12);
    const guardrailVersion = new bedrock.CfnGuardrailVersion(this, 'GuardrailVersion', {
      guardrailIdentifier: guardrail.attrGuardrailId, description: `Kiro Gateway policy ${policyHash}`,
    });

    // ---- state: data volume + snapshots, secrets, CA certificate --------------------------------
    // L1: the size is a template parameter (the L2 Volume validates sizes at synth time).
    const volume = new ec2.CfnVolume(this, 'Data', {
      availabilityZone: gwSubnet.availabilityZone, size: dataSize.valueAsNumber, volumeType: 'gp3', encrypted: true,
    });
    volume.cfnOptions.deletionPolicy = CfnDeletionPolicy.SNAPSHOT;   // a final snapshot on stack delete
    volume.cfnOptions.updateReplacePolicy = CfnDeletionPolicy.SNAPSHOT;
    Tags.of(volume).add(TAG_KEY, Aws.STACK_NAME);
    const snapshotRole = new iam.Role(this, 'SnapshotRole', {
      assumedBy: new iam.ServicePrincipal('dlm.amazonaws.com'),
      managedPolicies: [iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSDataLifecycleManagerServiceRole')],
    });
    new dlm.CfnLifecyclePolicy(this, 'Snapshots', {
      description: 'Kiro Gateway data volume daily snapshots', state: 'ENABLED', executionRoleArn: snapshotRole.roleArn,
      policyDetails: {
        resourceTypes: ['VOLUME'], targetTags: [{ key: TAG_KEY, value: Aws.STACK_NAME }],
        schedules: [{
          name: 'daily', copyTags: true,
          createRule: { interval: 24, intervalUnit: 'HOURS', times: ['03:00'] },
          retainRule: { count: snapshotDays.valueAsNumber },
        }],
      },
    });
    const consoleLogin = new secretsmanager.Secret(this, 'PortalLogin', {
      description: 'Kiro Gateway portal sign-in. The instance stores only a hash; rotate with scripts/console-passwd.sh.',
      generateSecretString: {
        secretStringTemplate: JSON.stringify({ username: 'admin' }), generateStringKey: 'password',
        passwordLength: 24, excludePunctuation: true,
      },
    });
    const originSecret = new secretsmanager.Secret(this, 'OriginVerify', {
      description: 'Shared secret CloudFront sends to the portal load balancer (requests without it are refused).',
      generateSecretString: {
        secretStringTemplate: '{}', generateStringKey: 'value', passwordLength: 40, excludePunctuation: true,
      },
    });
    const originSecretValue = originSecret.secretValueFromJson('value').unsafeUnwrap();   // a dynamic reference, not the value
    const caBackup = new secretsmanager.Secret(this, 'CaBackup', {
      description: 'Backup of the Kiro Gateway interception CA (key + certificate), written by the instance on first boot.',
      generateSecretString: { secretStringTemplate: '{}', generateStringKey: 'unset', passwordLength: 8, excludePunctuation: true },
    });
    const caCert = new ssm.StringParameter(this, 'CaCertificate', {
      description: 'Kiro Gateway CA certificate (public). Install it as a trusted root on Kiro clients.',
      stringValue: 'pending: written by the gateway instance on first boot',
    });
    const logGroup = new logs.LogGroup(this, 'Logs', {
      retention: logs.RetentionDays.THREE_MONTHS, removalPolicy: RemovalPolicy.RETAIN,
    });

    // ---- instance ------------------------------------------------------------------------------
    const role = new iam.Role(this, 'InstanceRole', {
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      description: 'Kiro Gateway instance: Session Manager, its guardrail, its volume, secrets and logs',
      managedPolicies: [iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore')],
    });
    role.addToPolicy(new iam.PolicyStatement({
      actions: ['bedrock:ApplyGuardrail'],
      resources: [guardrail.attrGuardrailArn, `${guardrail.attrGuardrailArn}:*`,
        `arn:${Aws.PARTITION}:bedrock:*:${Aws.ACCOUNT_ID}:guardrail-profile/*`],
    }));
    role.addToPolicy(new iam.PolicyStatement({
      actions: ['ec2:AttachVolume'],
      resources: [`arn:${Aws.PARTITION}:ec2:${Aws.REGION}:${Aws.ACCOUNT_ID}:volume/*`,
        `arn:${Aws.PARTITION}:ec2:${Aws.REGION}:${Aws.ACCOUNT_ID}:instance/*`],
      conditions: { StringEquals: { [`aws:ResourceTag/${TAG_KEY}`]: Aws.STACK_NAME } },
    }));
    role.addToPolicy(new iam.PolicyStatement({ actions: ['ec2:DescribeVolumes'], resources: ['*'] }));
    role.addToPolicy(new iam.PolicyStatement({ actions: ['cloudformation:SignalResource'], resources: [Aws.STACK_ID] }));
    logGroup.grantWrite(role);
    consoleLogin.grantRead(role);
    caBackup.grantRead(role);
    caBackup.grantWrite(role);
    caCert.grantWrite(role);

    let sourceEnv: string[];
    if (props.source === 'asset') {
      const asset = new s3assets.Asset(this, 'Source', {
        path: REPO_ROOT,
        exclude: ['.git', '.env', '.env.*', '!.env.example', 'pki', 'data', 'logs', 'deploy', '**/node_modules', '**/cdk.out*',
          'dashboard/work', 'dashboard/dist', 'dashboard/.cache', '**/__pycache__', '**/.ruff_cache', '*.pem', '*.key'],
      });
      asset.grantRead(role);
      Validations.of(role).acknowledge(...['Action::s3:GetObject*', 'Action::s3:GetBucket*', 'Action::s3:List*',
        'Resource::arn:<AWS::Partition>:s3:::cdk-hnb659fds-assets-<AWS::AccountId>-<AWS::Region>/*'].map((f) => ({
        id: `AwsSolutions-IAM5[${f}]`, reason: 'CDK asset read grant (development deploys only), scoped to the asset bucket.',
      })));
      sourceEnv = [`KGW_SOURCE_S3=${asset.s3ObjectUrl}`];
    } else {
      sourceEnv = [`KGW_SOURCE_REPO=${repoUrl!.valueAsString}`, `KGW_SOURCE_REF=${repoRef!.valueAsString}`];
    }

    const userData = ec2.UserData.forLinux();
    const asgLogicalId = 'GatewayAsg';
    const env: string[] = [
      `KGW_STACK=${Aws.STACK_NAME}`, `KGW_REGION=${Aws.REGION}`, `KGW_ASG_LOGICAL_ID=${asgLogicalId}`,
      `KGW_VOLUME_ID=${volume.ref}`, `KGW_LOG_GROUP=${logGroup.logGroupName}`,
      `KGW_PROXY_CIDR=${proxyCidr.valueAsString}`,
      `KGW_PORTAL_DNS=${portalLb.loadBalancerDnsName}`,
      `KGW_GUARDRAIL_ID=${guardrail.attrGuardrailId}`, `KGW_GUARDRAIL_VERSION=${guardrailVersion.attrVersion}`,
      `KGW_CONSOLE_SECRET=${consoleLogin.secretArn}`, `KGW_CA_SECRET=${caBackup.secretArn}`,
      `KGW_CA_PARAM=${caCert.parameterName}`, ...sourceEnv,
    ];
    userData.addCommands(...env.map((e) => `export ${e}`),
      readFileSync(path.join(__dirname, 'bootstrap.sh'), 'utf8'));

    const launchTemplate = new ec2.LaunchTemplate(this, 'LaunchTemplate', {
      // Latest Amazon Linux 2023, resolved at each launch (no AMI parameter to manage).
      machineImage: ec2.MachineImage.resolveSsmParameterAtLaunch(
        '/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64', { os: ec2.OperatingSystemType.LINUX }),
      instanceType: new ec2.InstanceType(instanceType.valueAsString),
      role, securityGroup: instanceSg, userData,
      requireImdsv2: true, httpPutResponseHopLimit: 2,   // 2 hops: containers (ml-guard) use the role too
      blockDevices: [{
        deviceName: '/dev/xvda',
        volume: ec2.BlockDeviceVolume.ebs(30, { encrypted: true, volumeType: ec2.EbsDeviceVolumeType.GP3 }),
      }],
    });
    const alarmTopic = new sns.Topic(this, 'Alarms', { displayName: 'Kiro Gateway alarms', enforceSSL: true });
    const hasEmail = new CfnCondition(this, 'HasAlarmEmail', {
      expression: Fn.conditionNot(Fn.conditionEquals(alarmEmail.valueAsString, '')),
    });
    new sns.CfnSubscription(this, 'AlarmEmailSubscription', {
      topicArn: alarmTopic.topicArn, protocol: 'email', endpoint: alarmEmail.valueAsString,
    }).cfnOptions.condition = hasEmail;

    const asg = new autoscaling.AutoScalingGroup(this, 'Gateway', {
      vpc, vpcSubnets: { subnets: [gwSubnet] }, launchTemplate, minCapacity: 1, maxCapacity: 1,
      healthChecks: autoscaling.HealthChecks.withAdditionalChecks({
        additionalTypes: [autoscaling.AdditionalHealthCheckType.ELB], gracePeriod: Duration.minutes(30),
      }),
      // CloudFormation waits for the bootstrap's cfn-signal: a failed first boot fails the deploy.
      signals: autoscaling.Signals.waitForMinCapacity({ timeout: Duration.minutes(45) }),
      // Replace = stop the old instance first (it holds the data volume), then boot the new one.
      updatePolicy: autoscaling.UpdatePolicy.rollingUpdate({
        minInstancesInService: 0, maxBatchSize: 1, waitOnResourceSignals: true, pauseTime: Duration.minutes(45),
      }),
      notifications: [{ topic: alarmTopic }],
    });
    (asg.node.defaultChild as autoscaling.CfnAutoScalingGroup).overrideLogicalId(asgLogicalId);
    Tags.of(asg).add(TAG_KEY, Aws.STACK_NAME, { applyToLaunchedInstances: true });
    Tags.of(asg).add('Name', `${Aws.STACK_NAME}-gateway`, { applyToLaunchedInstances: true });

    const portalListener = portalLb.addListener('Http', {
      port: 80, protocol: elbv2.ApplicationProtocol.HTTP, open: false,
      defaultAction: elbv2.ListenerAction.fixedResponse(403, { contentType: 'text/plain', messageBody: 'Forbidden' }),
    });
    const portalTg = new elbv2.ApplicationTargetGroup(this, 'PortalTargets', {
      vpc, port: PORTAL_PORT, protocol: elbv2.ApplicationProtocol.HTTPS, targets: [asg],
      deregistrationDelay: Duration.seconds(30),
      healthCheck: { path: '/api/health', protocol: elbv2.Protocol.HTTPS, healthyHttpCodes: '200', interval: Duration.seconds(30) },
    });
    portalListener.addAction('FromCloudFront', {
      priority: 1, conditions: [elbv2.ListenerCondition.httpHeader(ORIGIN_HEADER, [originSecretValue])],
      action: elbv2.ListenerAction.forward([portalTg]),
    });

    // ---- CloudFront + AWS WAF ----------------------------------------------------------------------
    const isUsEast1 = new CfnCondition(this, 'IsUsEast1', { expression: Fn.conditionEquals(Aws.REGION, 'us-east-1') });
    const createAcl = new CfnCondition(this, 'CreateWebAcl', {
      expression: Fn.conditionAnd(isUsEast1, Fn.conditionEquals(webAclParam.valueAsString, '')),
    });
    new CfnRule(this, 'WebAclAvailable', {
      assertions: [{
        assert: Fn.conditionOr(Fn.conditionEquals(Aws.REGION, 'us-east-1'),
          Fn.conditionNot(Fn.conditionEquals(webAclParam.valueAsString, ''))),
        assertDescription: 'Outside us-east-1, set CloudFrontWebAclArn (CloudFront web ACLs must be created in us-east-1).',
      }],
    });
    const webAcl = this.portalWebAcl();
    webAcl.cfnOptions.condition = createAcl;
    const distribution = new cloudfront.Distribution(this, 'Portal', {
      comment: `${Aws.STACK_NAME} portal`,
      defaultBehavior: {
        origin: origins.VpcOrigin.withApplicationLoadBalancer(portalLb, {
          httpPort: 80, protocolPolicy: cloudfront.OriginProtocolPolicy.HTTP_ONLY,
          customHeaders: { [ORIGIN_HEADER]: originSecretValue }, readTimeout: Duration.seconds(60),
        }),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
        cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,   // every response is per-user
        // all viewer headers (Host for the CSRF origin check, cookies) + CloudFront-Viewer-Address
        originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER_AND_CLOUDFRONT_2022,
      },
      priceClass: cloudfront.PriceClass.PRICE_CLASS_100,
      httpVersion: cloudfront.HttpVersion.HTTP2_AND_3,
      webAclId: Fn.conditionIf(createAcl.logicalId, webAcl.attrArn, webAclParam.valueAsString).toString(),
    });
    const proxyTg = proxyLb.addListener('Proxy', { port: PROXY_PORT, protocol: elbv2.Protocol.TCP }).addTargets('Squid', {
      port: PROXY_PORT, protocol: elbv2.Protocol.TCP, targets: [asg], preserveClientIp: true,
      deregistrationDelay: Duration.seconds(30), healthCheck: { protocol: elbv2.Protocol.TCP, interval: Duration.seconds(30) },
    });

    // ---- alarms --------------------------------------------------------------------------------
    const healthy = { period: Duration.minutes(1), statistic: 'Minimum' };
    for (const [name, metric] of [['Portal', portalTg.metrics.healthyHostCount(healthy)],
      ['Proxy', proxyTg.metrics.healthyHostCount(healthy)]] as const) {
      new cloudwatch.Alarm(this, `${name}Unhealthy`, {
        alarmDescription: `Kiro Gateway ${name.toLowerCase()} has no healthy target for 5 minutes`,
        metric,
        threshold: 1, comparisonOperator: cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
        evaluationPeriods: 5, treatMissingData: cloudwatch.TreatMissingData.BREACHING,
      }).addAlarmAction(new cwActions.SnsAction(alarmTopic));
    }

    // ---- outputs + console layout ---------------------------------------------------------------
    new CfnOutput(this, 'PortalUrl', {
      value: `https://${distribution.distributionDomainName}/`,
      description: 'Portal (CloudFront + AWS WAF; sign in with PortalLoginSecret)',
    });
    new CfnOutput(this, 'ProxyEndpoint', {
      value: `http://${proxyLb.loadBalancerDnsName}:${PROXY_PORT}`, description: 'HTTPS_PROXY for Kiro clients',
    });
    new CfnOutput(this, 'PortalLoginSecret', {
      value: consoleLogin.secretName,
      description: 'aws secretsmanager get-secret-value --secret-id <this> --query SecretString --output text',
    });
    new CfnOutput(this, 'CaCertificateParameter', {
      value: caCert.parameterName,
      description: 'aws ssm get-parameter --name <this> --query Parameter.Value --output text > kiro-gateway-ca.crt',
    });
    new CfnOutput(this, 'GuardrailId', { value: guardrail.attrGuardrailId });
    new CfnOutput(this, 'LogGroup', { value: logGroup.logGroupName });
    new CfnOutput(this, 'AutoScalingGroup', {
      value: asg.autoScalingGroupName, description: 'Shell: aws ssm start-session --target <instance id of this group>',
    });

    this.templateOptions.metadata = {
      'AWS::CloudFormation::Interface': {
        ParameterGroups: [
          { Label: { default: 'Access' }, Parameters: ['ProxyAllowedCidr', 'CloudFrontWebAclArn'] },
          ...groups.map((g) => ({ Label: { default: g.label }, Parameters: g.parameters })),
          { Label: { default: 'Instance and storage' }, Parameters: ['InstanceType', 'DataVolumeSize', 'SnapshotRetentionDays'] },
          ...(props.source === 'git' ? [{ Label: { default: 'Source' }, Parameters: ['SourceRepoUrl', 'SourceRef'] }] : []),
          { Label: { default: 'Notifications' }, Parameters: ['AlarmEmail'] },
        ],
      },
    };

    for (const sg of [portalLbSg, proxyLbSg]) {
      Validations.of(sg).acknowledge({
        id: 'AwsSolutions::AwsSolutions-EC23',
        reason: 'Ingress CIDR is the VPC range or a template parameter; the NotOpenToTheWorld rule refuses 0.0.0.0/0.',
      });
    }
    Validations.of(distribution).acknowledge(
      { id: 'AwsSolutions-CFR1', reason: 'No geo restriction by design: access control is AWS WAF + the portal sign-in.' },
      { id: 'AwsSolutions-CFR3', reason: 'The gateway logs every portal request itself (console log, CloudWatch); WAF samples requests.' },
      { id: 'AwsSolutions-CFR4', reason: 'Default *.cloudfront.net certificate (no custom domain); add a domain + ACM certificate to enforce TLSv1.2_2021.' },
    );
    Validations.of(portalLb).acknowledge(
      { id: 'AwsSolutions-ELB2', reason: 'Internal ALB behind CloudFront; the gateway logs every request itself (console log, CloudWatch).' },
    );
    this.suppressNagFindings(role, asg, [proxyLb], [consoleLogin, caBackup, originSecret], alarmTopic, snapshotRole);
  }

  /**
   * AWS WAF for the portal (CLOUDFRONT scope, so it can only be created in us-east-1).
   * Rate limits per viewer IP, AWS IP reputation, known bad inputs and the common rule set. The
   * common rules' BODY/size checks run in COUNT mode: prompts, rule patterns and Grafana queries
   * legitimately contain code, regexes and long bodies, and inspecting them is the gateway's job.
   */
  private portalWebAcl(): wafv2.CfnWebACL {
    const vis = (name: string) => ({ cloudWatchMetricsEnabled: true, metricName: name, sampledRequestsEnabled: true });
    const managed = (name: string, priority: number, countRules: string[] = []) => ({
      name, priority, overrideAction: { none: {} }, visibilityConfig: vis(name),
      statement: { managedRuleGroupStatement: {
        vendorName: 'AWS', name, ruleActionOverrides: countRules.map((r) => ({ name: r, actionToUse: { count: {} } })),
      } },
    });
    return new wafv2.CfnWebACL(this, 'PortalWebAcl', {
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

  /** Every cdk-nag exception, with the reason it is acceptable here. */
  private suppressNagFindings(role: iam.Role, asg: autoscaling.AutoScalingGroup, lbs: elbv2.NetworkLoadBalancer[],
    secrets: secretsmanager.Secret[], topic: sns.Topic, snapshotRole: iam.Role): void {
    const iam5 = (resource: string, reason: string) => ({ id: `AwsSolutions-IAM5[Resource::${resource}]`, reason });
    Validations.of(role).acknowledge(
      { id: 'AwsSolutions-IAM4[Policy::arn:<AWS::Partition>:iam::aws:policy/AmazonSSMManagedInstanceCore]',
        reason: 'AWS-maintained policy for Session Manager, which replaces SSH (no inbound port, audited sessions).' },
      iam5('*', 'ec2:DescribeVolumes has no resource-level permissions.'),
      iam5('<Guardrail.GuardrailArn>:*', 'Versions of this stack\'s own guardrail.'),
      iam5('arn:<AWS::Partition>:bedrock:*:<AWS::AccountId>:guardrail-profile/*',
        'Cross-region guardrail profile: Bedrock may evaluate the guardrail in any region of the profile.'),
      iam5('arn:<AWS::Partition>:ec2:<AWS::Region>:<AWS::AccountId>:instance/*', 'AttachVolume is limited to resources tagged with this stack.'),
      iam5('arn:<AWS::Partition>:ec2:<AWS::Region>:<AWS::AccountId>:volume/*', 'AttachVolume is limited to resources tagged with this stack.'),
    );
    Validations.of(snapshotRole).acknowledge(
      { id: 'AwsSolutions-IAM4[Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSDataLifecycleManagerServiceRole]',
        reason: 'AWS-maintained policy for EBS snapshot automation (Data Lifecycle Manager).' },
    );
    for (const lb of lbs) {
      Validations.of(lb).acknowledge(
        { id: 'AwsSolutions-ELB2', reason: 'TCP pass-through listeners: NLB access logs only cover TLS listeners. The gateway logs every request itself (audit log, Loki).' },
      );
    }
    for (const s of secrets) {
      Validations.of(s).acknowledge(
        { id: 'AwsSolutions-SMG4', reason: 'Not rotatable by Secrets Manager: the portal password is hashed on the instance (scripts/console-passwd.sh) and the CA is a backup copy.' },
      );
    }
    Validations.of(topic).acknowledge(
      { id: 'AwsSolutions-SNS2', reason: 'CloudWatch alarms cannot publish to a topic encrypted with the AWS managed key; the messages are health notices with no sensitive data.' },
    );
    Validations.of(asg).acknowledge(
      { id: 'AwsSolutions-AS3', reason: 'Notifications for all scaling events are configured (notifications: alarm topic).' },
    );
  }
}
