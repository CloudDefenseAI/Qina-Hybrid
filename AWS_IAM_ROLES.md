# AWS IAM Roles Created During CloudDefense Hybrid Onboarding

This document details all IAM roles created in your AWS account during the CloudDefense Hybrid onboarding process via CloudFormation.

## Roles Created

The CloudFormation template creates three IAM roles:

1. **EventBridge Role** - `Cdefense-{Region}-{CloudDefenseAccountId}-BridgeRole3b12043b41`
2. **CloudDefense Cross-Account IAM Role** - `{ExternalId}-cdefense-hybrid-role`
3. **Lambda Execution Role** - `CloudDefenseHybridSetupSt-HybridLambdaExecutionRole-{UniqueId}`

---

## 1. EventBridge Role

**Role Name Example**: `Cdefense-us-east-1-407638845061-BridgeRole3b12043b41`

```json
{
  "Role": {
    "RoleName": "Cdefense-us-east-1-407638845061-BridgeRole3b12043b41",
    "Arn": "arn:aws:iam::123456789012:role/Cdefense-us-east-1-407638845061-BridgeRole3b12043b41",
    "AssumeRolePolicyDocument": {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": {
            "Service": "events.amazonaws.com"
          },
          "Action": "sts:AssumeRole"
        }
      ]
    }
  }
}
```

**Inline Policy**: `AllowPushEventsToCloudDefense`

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "events:PutEvents",
      "Resource": "arn:aws:events:*:407638845061:event-bus/default"
    }
  ]
}
```

---

## 2. CloudDefense Cross-Account IAM Role

**Role Name Example**: `abc123xyz-cdefense-hybrid-role`

```json
{
  "Role": {
    "RoleName": "abc123xyz-cdefense-hybrid-role",
    "Arn": "arn:aws:iam::123456789012:role/abc123xyz-cdefense-hybrid-role",
    "MaxSessionDuration": 43200,
    "AssumeRolePolicyDocument": {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": {
            "AWS": "arn:aws:iam::407638845061:root"
          },
          "Action": "sts:AssumeRole",
          "Condition": {
            "StringEquals": {
              "sts:ExternalId": "abc123xyz"
            }
          }
        }
      ]
    }
  }
}
```

**Inline Policy**: `LambdaInvokePolicy`

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "lambda:InvokeFunction",
        "lambda:InvokeFunctionUrl"
      ],
      "Resource": "arn:aws:lambda:us-east-1:123456789012:function:HybridLambdaFunction3b12043b41"
    }
  ]
}
```

---

## 3. Lambda Execution Role

**Role Name Example**: `CloudDefenseHybridSetupSt-HybridLambdaExecutionRole-ABCD1234`

```json
{
  "Role": {
    "RoleName": "CloudDefenseHybridSetupSt-HybridLambdaExecutionRole-ABCD1234",
    "Arn": "arn:aws:iam::123456789012:role/CloudDefenseHybridSetupSt-HybridLambdaExecutionRole-ABCD1234",
    "AssumeRolePolicyDocument": {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": {
            "Service": "lambda.amazonaws.com"
          },
          "Action": "sts:AssumeRole"
        }
      ]
    }
  }
}
```

**Managed Policy Attached**:
- `arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole`

**Inline Policy**: `HybridLambdaPolicy`

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "eks:DescribeCluster",
        "sts:GetCallerIdentity"
      ],
      "Resource": "arn:aws:eks:us-east-1:123456789012:cluster/cdefense-hybrid"
    }
  ]
}
```

---

## Summary of All Roles

```json
{
  "Roles": [
    {
      "RoleName": "Cdefense-us-east-1-407638845061-BridgeRole3b12043b41",
      "Arn": "arn:aws:iam::123456789012:role/Cdefense-us-east-1-407638845061-BridgeRole3b12043b41",
      "Purpose": "EventBridge role for forwarding events to CloudDefense",
      "TrustedEntity": "events.amazonaws.com",
      "Permissions": "events:PutEvents"
    },
    {
      "RoleName": "abc123xyz-cdefense-hybrid-role",
      "Arn": "arn:aws:iam::123456789012:role/abc123xyz-cdefense-hybrid-role",
      "Purpose": "Cross-account role for CloudDefense to invoke Lambda",
      "TrustedEntity": "arn:aws:iam::407638845061:root",
      "Condition": "External ID: abc123xyz",
      "Permissions": "lambda:InvokeFunction, lambda:InvokeFunctionUrl",
      "MaxSessionDuration": "43200 seconds (12 hours)"
    },
    {
      "RoleName": "CloudDefenseHybridSetupSt-HybridLambdaExecutionRole-ABCD1234",
      "Arn": "arn:aws:iam::123456789012:role/CloudDefenseHybridSetupSt-HybridLambdaExecutionRole-ABCD1234",
      "Purpose": "Lambda execution role with VPC and EKS access",
      "TrustedEntity": "lambda.amazonaws.com",
      "Permissions": "VPC access, EKS describe, CloudWatch Logs"
    }
  ]
}
```

---

## CloudFormation Parameters

| Parameter | Description | Example Value |
|-----------|-------------|---------------|
| `Data[0]` | External ID (randomly generated) | `abc123xyz` |
| `Data[1]` | CloudDefense Account ID | `407638845061` |

**Note**: Replace `123456789012` with your actual AWS account ID.
