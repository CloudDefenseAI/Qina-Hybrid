# CloudDefense Hybrid Deployment - IAM Policy Documentation

## Overview
This document explains the IAM policies required for deploying CloudDefense Hybrid infrastructure, which includes:
1. **EKS Cluster** (via eksctl)
2. **CloudFormation Stack** (Lambda, IAM Roles, EventBridge, Custom Resources)

---

## Policy Configuration

### **AWS Managed Policies** (5 Total)

#### 1. **AmazonEC2FullAccess**
**Purpose:** EKS Cluster & VPC Infrastructure Creation

**Used For:**
- Creating VPC, Subnets, Internet Gateway, NAT Gateway
- Creating Route Tables and Routes
- Creating Security Groups and Rules
- Allocating Elastic IPs
- Creating and managing EC2 instances for EKS node groups
- Creating Launch Templates for node groups
- Describing instance types, availability zones, and offerings
- Managing network interfaces and VPC attributes

**Resources Created:**
- VPC with public/private subnets
- Single NAT Gateway (as per eksctl config)
- Security groups for EKS cluster and node groups
- EC2 instances for managed node group (t3.small)

---

#### 2. **AmazonEKSClusterPolicy**
**Purpose:** EKS Cluster Management

**Used For:**
- Creating and managing EKS cluster
- Creating and managing EKS node groups
- Tagging EKS resources
- Load balancer operations (Classic, ALB, NLB)
- Service-linked role operations

**Resources Created:**
- EKS cluster: `cdefense-hybrid` (version 1.30)
- Managed node group: `cdefense-hybrid-ng`
- EKS cluster IAM role
- Node group IAM role

---

#### 3. **AWSCloudFormationFullAccess**
**Purpose:** CloudFormation Stack Deployment

**Used For:**
- Creating CloudFormation stack
- Describing stacks and stack events
- Getting template summaries
- Managing stack resources
- Handling stack rollbacks and updates

**Resources Created:**
- CloudFormation stack containing:
  - IAM roles (3 roles)
  - Lambda function and function URL
  - Custom resource for CloudDefense integration
  - EventBridge role

---

#### 4. **AWSLambda_FullAccess**
**Purpose:** Lambda Function Management

**Used For:**
- Creating Lambda functions
- Creating Lambda function URLs
- Configuring Lambda permissions
- Managing Lambda execution roles
- Setting environment variables
- Tagging Lambda resources

**Resources Created:**
- `HybridLambdaFunction3b12043b41` (Python 3.9 runtime)
- Lambda Function URL with AWS_IAM auth
- Lambda execution role with VPC access

---

#### 5. **AWSCloudShellFullAccess**
**Purpose:** Optional - CloudShell Access

**Used For:**
- Accessing AWS CloudShell for command-line operations
- Running eksctl commands from CloudShell
- Troubleshooting and debugging

**Note:** This policy is optional and only needed if deploying via CloudShell.

---

## Custom Inline Policy: `hybrid-setup-custom`

### **Statement 1: IAM Role Management**
**Purpose:** Create and manage IAM roles without full IAM access

**Actions:**
- Create/Delete IAM roles
- Attach/Detach managed policies to roles
- Create/Update/Delete inline policies
- Pass roles to services
- Tag/Untag roles
- Create service-linked roles

**CloudFormation Resources:**
- `CDIAMRole3b12043b41` - Cross-account assume role for CloudDefense
- `EvBridgeRole3b12043b41` - EventBridge role for sending events
- `HybridLambdaExecutionRole3b12043b41` - Lambda execution role

**EKS Resources:**
- EKS cluster service role
- EKS node group instance role
- Service-linked roles for EKS and Auto Scaling

---

### **Statement 2: EKS Full Management**
**Purpose:** Complete EKS operations

**Actions:**
- All EKS operations (`eks:*`)

**Used For:**
- Creating cluster with specific configuration
- Creating managed node groups
- Updating cluster version
- Managing add-ons
- Configuring cluster endpoints (public + private access)

---

### **Statement 3: Auto Scaling Management**
**Purpose:** Node group auto-scaling

**Actions:**
- All Auto Scaling operations (`autoscaling:*`)

**Used For:**
- Creating Auto Scaling groups for node groups
- Setting desired capacity (1), min (1), max (1)
- Creating launch configurations/templates
- Managing scaling policies

---

### **Statement 4: S3 Read Access**
**Purpose:** Access Lambda code from external S3 bucket

**Actions:**
- `s3:GetObject` - Download Lambda deployment package
- `s3:ListBucket` - List bucket contents

**Used For:**
- Downloading `GITLAB_lambda_function.zip` from:
  - Bucket: `cdefense-hybrid-lambda-bucket-{region}`
  - Region-specific bucket (e.g., ap-south-1)

**Note:** The S3 bucket is in a different AWS account (public access configured)

---

### **Statement 5: SNS Publish**
**Purpose:** Send custom resource notifications to CloudDefense

**Actions:**
- `sns:Publish` - Send messages to SNS topic
- `sns:Subscribe` - Subscribe to topics

**Used For:**
- Custom resource `CbMothership3b12043b41` sends deployment info to:
  - SNS Topic: `arn:aws:sns:us-west-2:407638845061:cdefense-hybrid-setup-qa`
  - Account: 407638845061 (CloudDefense account)
  
**Data Sent:**
- Role ARN, Account ID, External ID
- Lambda Function URL
- Tenant ID and source control type

---

### **Statement 6: CloudWatch Logs**
**Purpose:** Lambda and EKS logging

**Actions:**
- Create log groups and log streams
- Put log events
- Describe log groups

**Used For:**
- Lambda function logs: `/aws/lambda/HybridLambdaFunction3b12043b41`
- EKS cluster logs (if enabled)
- Node group logs

---

### **Statement 7: STS Get Caller Identity**
**Purpose:** Identity verification

**Actions:**
- `sts:GetCallerIdentity`

**Used For:**
- Lambda function to verify its execution context
- CloudFormation to validate credentials
- eksctl to verify AWS account

---

### **Statement 8: Access Analyzer**
**Purpose:** IAM policy validation

**Actions:**
- `access-analyzer:ListPolicyGenerations`

**Used For:**
- Validating IAM policies during creation
- Checking for policy errors or warnings

---

## Resources Created Summary

### **By eksctl (EKS Cluster)**
1. VPC with CIDR block
2. 3 Public Subnets (across availability zones)
3. 3 Private Subnets (across availability zones)
4. 1 Internet Gateway
5. 1 NAT Gateway (single mode)
6. Route Tables and Routes
7. Security Groups
8. EKS Cluster: `cdefense-hybrid` (v1.30)
9. Managed Node Group: `cdefense-hybrid-ng` (1x t3.small)
10. Auto Scaling Group
11. Launch Template
12. IAM Roles (cluster + node group)

### **By CloudFormation Stack**
1. **CDIAMRole3b12043b41** - Cross-account role with trust to CloudDefense account
2. **EvBridgeRole3b12043b41** - EventBridge role for sending events
3. **HybridLambdaExecutionRole3b12043b41** - Lambda execution role with VPC access
4. **HybridLambdaFunction3b12043b41** - Lambda function (Python 3.9)
5. **HybridLambdaFunction3b12043b41Url3b12043b41** - Lambda Function URL
6. **CbMothership3b12043b41** - Custom resource for CloudDefense integration

---

## Security Considerations

### **Least Privilege Approach**
- No IAM Full Access (only role management permissions)
- S3 access limited to GetObject and ListBucket
- SNS access limited to Publish and Subscribe
- CloudWatch limited to log operations

### **Cross-Account Trust**
- CloudDefense account (407638845061) can assume `CDIAMRole3b12043b41`
- External ID validation for secure cross-account access
- Lambda function URL requires AWS_IAM authentication

### **Network Security**
- EKS cluster endpoints: public + private access
- Node groups in private subnets
- Single NAT gateway for egress
- Security groups restrict access

---

## Deployment Flow

### **Step 1: EKS Cluster Creation**
```bash
eksctl create cluster -f cluster.yml
```

**Policies Used:**
- AmazonEC2FullAccess
- AmazonEKSClusterPolicy
- Custom: EKS Full Management, Auto Scaling, IAM Role Management, STS

### **Step 2: CloudFormation Stack Deployment**
```bash
aws cloudformation create-stack --stack-name clouddefense-hybrid \
  --template-body file://template.json \
  --parameters ParameterKey=Data,ParameterValue=<external-id>,<clouddefense-account-id> \
  --capabilities CAPABILITY_NAMED_IAM
```

**Policies Used:**
- AWSCloudFormationFullAccess
- AWSLambda_FullAccess
- Custom: IAM Role Management, S3 Read, SNS Publish, CloudWatch Logs

---

## Validation Checklist

- [ ] All 5 AWS managed policies attached to user
- [ ] Custom inline policy created with all 8 statements
- [ ] User can access external S3 bucket for Lambda code
- [ ] User can publish to external SNS topic
- [ ] eksctl successfully creates cluster
- [ ] CloudFormation stack deploys without errors
- [ ] Lambda function URL is accessible
- [ ] CloudDefense receives custom resource notification

---

## Troubleshooting

### **Common Issues & Required Policies**

| Error Message | Missing Policy/Permission |
|---------------|---------------------------|
| `UnauthorizedOperation: ec2:DescribeInstanceTypeOfferings` | AmazonEC2FullAccess |
| `User is not authorized to perform: eks:CreateCluster` | AmazonEKSClusterPolicy or Custom EKS Full Management |
| `User is not authorized to perform: iam:CreateRole` | Custom IAM Role Management |
| `AccessDenied: s3:GetObject` | Custom S3 Read Access + Bucket policy in source account |
| `AccessDenied: sns:Publish` | Custom SNS Publish + Topic policy in destination account |
| `User is not authorized to perform: cloudformation:CreateStack` | AWSCloudFormationFullAccess |

---

## Maintenance Notes

- AWS managed policies are automatically updated by AWS
- Custom policy may need updates for new features
- Review policies quarterly for least privilege compliance
- Monitor CloudTrail for denied API calls
- Update Lambda runtime version in CloudFormation template as needed