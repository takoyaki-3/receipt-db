import * as path from 'node:path';
import * as cdk from 'aws-cdk-lib';
import * as apigw from 'aws-cdk-lib/aws-apigateway';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as s3deploy from 'aws-cdk-lib/aws-s3-deployment';
import { Construct } from 'constructs';

export class Takoyaki3ReceiptStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const allowedEmails = new cdk.CfnParameter(this, 'AllowedEmails', {
      type: 'CommaDelimitedList',
      noEcho: true,
      description: 'Firebase email addresses permitted to use the receipt app',
    });
    const firebaseProjectId = new cdk.CfnParameter(this, 'FirebaseProjectId', {
      type: 'String',
      default: 'takoyaki3-auth',
    });

    const receiptsTable = new dynamodb.Table(this, 'ReceiptsTable', {
      partitionKey: { name: 'user_id', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'receipt_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    const imagesBucket = new s3.Bucket(this, 'ReceiptImagesBucket', {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      versioned: true,
      lifecycleRules: [{ noncurrentVersionExpiration: cdk.Duration.days(30) }],
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    const receiptFunction = new lambda.Function(this, 'ReceiptFunction', {
      runtime: lambda.Runtime.PYTHON_3_12,
      architecture: lambda.Architecture.ARM_64,
      handler: 'receipt_api.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '..', 'lambda')),
      timeout: cdk.Duration.seconds(29),
      memorySize: 512,
      environment: {
        RECEIPTS_TABLE_NAME: receiptsTable.tableName,
        IMAGES_BUCKET_NAME: imagesBucket.bucketName,
        ALLOWED_EMAILS: cdk.Fn.join(',', allowedEmails.valueAsList),
      },
    });
    receiptsTable.grantReadWriteData(receiptFunction);
    imagesBucket.grantReadWrite(receiptFunction);
    receiptFunction.addToRolePolicy(new iam.PolicyStatement({
      actions: ['textract:AnalyzeExpense'],
      resources: ['*'],
    }));

    const authFunction = new lambda.Function(this, 'AuthFunction', {
      runtime: lambda.Runtime.PYTHON_3_12,
      architecture: lambda.Architecture.ARM_64,
      handler: 'receipt_api.authorizer',
      code: lambda.Code.fromAsset(path.join(__dirname, '..', 'lambda')),
      timeout: cdk.Duration.seconds(10),
      memorySize: 128,
      environment: { FIREBASE_PROJECT_ID: firebaseProjectId.valueAsString },
    });

    const api = new apigw.RestApi(this, 'ReceiptRestApi', {
      description: 'Firebase-authenticated receipt OCR and archive API',
      endpointTypes: [apigw.EndpointType.REGIONAL],
      binaryMediaTypes: [],
      deployOptions: {
        stageName: 'prod',
        throttlingBurstLimit: 10,
        throttlingRateLimit: 5,
        loggingLevel: apigw.MethodLoggingLevel.ERROR,
        dataTraceEnabled: false,
        metricsEnabled: true,
      },
      defaultCorsPreflightOptions: {
        allowHeaders: ['Authorization', 'Content-Type'],
        allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        allowOrigins: apigw.Cors.ALL_ORIGINS,
      },
    });
    const gatewayHeaders = {
      'Access-Control-Allow-Origin': "'*'",
      'Access-Control-Allow-Headers': "'Authorization,Content-Type'",
      'Access-Control-Allow-Methods': "'GET,POST,PUT,DELETE,OPTIONS'",
    };
    api.addGatewayResponse('Default4xx', {
      type: apigw.ResponseType.DEFAULT_4XX,
      responseHeaders: gatewayHeaders,
    });
    api.addGatewayResponse('Default5xx', {
      type: apigw.ResponseType.DEFAULT_5XX,
      responseHeaders: gatewayHeaders,
    });

    const authorizer = new apigw.TokenAuthorizer(this, 'FirebaseAuthorizer', {
      handler: authFunction,
      identitySource: apigw.IdentitySource.header('Authorization'),
      resultsCacheTtl: cdk.Duration.seconds(0),
    });
    const protectedOptions: apigw.MethodOptions = {
      authorizer,
      authorizationType: apigw.AuthorizationType.CUSTOM,
    };
    const integration = new apigw.LambdaIntegration(receiptFunction);
    const receipts = api.root.addResource('receipts');
    receipts.addMethod('GET', integration, protectedOptions);
    receipts.addMethod('POST', integration, protectedOptions);
    const receipt = receipts.addResource('{id}');
    receipt.addMethod('GET', integration, protectedOptions);
    receipt.addMethod('PUT', integration, protectedOptions);
    receipt.addMethod('DELETE', integration, protectedOptions);

    const webBucket = new s3.Bucket(this, 'WebBucket', {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    const apiBehavior: cloudfront.BehaviorOptions = {
      origin: new origins.HttpOrigin(
        `${api.restApiId}.execute-api.${this.region}.${this.urlSuffix}`,
        { originPath: '/prod', protocolPolicy: cloudfront.OriginProtocolPolicy.HTTPS_ONLY },
      ),
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
      cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
      originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
    };
    const distribution = new cloudfront.Distribution(this, 'WebDistribution', {
      defaultRootObject: 'index.html',
      defaultBehavior: {
        origin: origins.S3BucketOrigin.withOriginAccessControl(webBucket),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD_OPTIONS,
        cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED,
        responseHeadersPolicy: cloudfront.ResponseHeadersPolicy.SECURITY_HEADERS,
      },
      additionalBehaviors: { 'receipts*': apiBehavior },
    });
    new s3deploy.BucketDeployment(this, 'DeployWeb', {
      sources: [s3deploy.Source.asset(path.join(__dirname, '..', 'web'))],
      destinationBucket: webBucket,
      distribution,
      distributionPaths: ['/*'],
    });

    new cdk.CfnOutput(this, 'WebUrl', {
      value: `https://${distribution.distributionDomainName}`,
      description: 'Receipt app URL',
    });
    new cdk.CfnOutput(this, 'ApiUrl', { value: api.url, description: 'Receipt API URL' });
    new cdk.CfnOutput(this, 'ReceiptsTableName', { value: receiptsTable.tableName });
    new cdk.CfnOutput(this, 'ImagesBucketName', { value: imagesBucket.bucketName });
  }
}
