#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { Takoyaki3ReceiptStack } from '../lib/takoyaki3-receipt-stack';

const app = new cdk.App();
new Takoyaki3ReceiptStack(app, 'Takoyaki3ReceiptStack', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION ?? 'ap-northeast-1',
  },
});

