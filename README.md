# Qina-Hybrid
Qina Hybrid setup for SAST/SCA

## 1. Go Integration Setup and CloudFormation Creation

### Initial Setup in CloudDefense Dashboard

1. In the CloudDefense dashboard, navigate to **Integration → GitHub**.
2. Fill in the required details (AWS account number). 
   > **Note**: Do not fill GitHub token here directly.
3. Select the Region in which you have the cluster and want to create the Lambda.
4. Click **Create CloudFormation template** button.
5. Acknowledge that AWS CloudFormation will create resources and click **Create Stack**.

Wait for the CloudFormation stack to complete successfully before proceeding to the next steps.

## 2. Lambda Configuration and Scanner Image Setup

After CloudFormation completes, a Lambda function will be created. Perform the following updates:

### Environment Variables

Configure the following environment variables in your Lambda function:

| Variable | Description |
|----------|-------------|
| `EKS_CLUSTER_NAME` | Your Kubernetes cluster name |
| `GITHUB_USERNAME` | Your GitHub username |
| `GITHUB_TOKEN` | Your GitHub token |
| `AWS_REGION_HYBRID` | AWS region of the cluster |
| `AWS_ACCESS_KEY_ID_HYBRID` | AWS S3 access key |
| `AWS_SECRET_ACCESS_KEY_HYBRID` | AWS S3 secret key |
| `BUCKET_NAME_HYBRID` | AWS S3 bucket name |
| `CLI_IMAGE` | Cdefense CLI scanner image |
| `IS_ENTERPRISE` | Set to `false` |
| `GIT_ENTERPRISE_URL` | Your Source GIT enterprise URL |

### Networking Configuration

Configure the Lambda networking settings:

- Attach the Lambda to the same VPC as your Kubernetes cluster
- Select the Security Group used by your cluster
- Make sure that VPC and subnet have access to the Internet

## 3. IAM Role Updates

1. Go to the IAM Role created by CloudFormation (e.g., `CloudDefenseHybridSetupSt-HybridLambdaExecutionRole-*`).
2. Edit the inline policy to update the cluster ARN with your own .

## 4. Kubernetes Access Setup

1. Log in to the Kubernetes cluster that will be used for running jobs.
2. Run the following command:
   ```bash
   kubectl edit configmap aws-auth -n kube-system
   ```
3. Add a new group entry to provide the Lambda role access:
   ```yaml
   - groups:
     - system:masters
     rolearn: arn:aws:iam::1234567890:role/CloudDefenseHybridSetupSt-HybridLambdaExecutionRole*
   ```
   > **Note**: Use the role ARN dynamically created from CloudFormation
4. Save and exit the editor.

## 5. Add Image Secret

To pull the private full scan image, create a Docker registry secret:

```bash
kubectl create secret docker-registry image-secret \
  --docker-server=https://index.docker.io/v1/ \
  --docker-username=YOUR_DOCKERHUB_USERNAME \
  --docker-password=YOUR_DOCKERHUB_PASSWORD \
  --docker-email=YOUR_EMAIL
```

## 6. Verify the Secret

Confirm that the secret has been added successfully:

```bash
kubectl get secrets
kubectl describe secret image-secret
```

✅ **Setup Complete**: At this point, the Lambda function will have network access and RBAC permissions to run jobs on the Kubernetes cluster.

---

## Scanner Job Information

The `CLI_IMAGE` environment variable stored in the Lambda function contains the scanner, which is a code-analysis utility that automatically runs:

- **SAST** (Static Application Security Testing)
- **SCA** (Software Composition Analysis)
- **Secrets Detection**

Once the repository is cloned, the scanner inspects the source code for security flaws, dependency vulnerabilities, and exposed secrets.

## Metadata Reporting to QINA

After completing a scan, the tool generates structured metadata and sends it to the QINA backend. This metadata provides both a high-level overview and detailed examples of detected issues.

### Example Metadata

```json
{
  "summary": {
    "total_vulnerabilities": 8,
    "critical": 6,
    "high": 2,
    "affected_file": "/app/a.py",
    "main_issue": "SQL Injection via user input"
  },
  "example_vulnerability": {
    "rule_id": "flask-prestodb-sqli",
    "severity": "CRITICAL",
    "cwe": "CWE-89",
    "taint_source": "request.args.get('username')",
    "sink": "cursor.execute(query)",
    "line": 28
  }
}
```

### Key Points

- **Summary Block**: Captures total vulnerabilities, severity breakdown, the most affected file, and the primary issue
- **Example Vulnerability Block**: Highlights a specific vulnerability with details such as rule ID, severity, CWE classification, taint source, sink, and line number
- **Integration with QINA**: By sending these results to QINA, security findings are centralized, enabling easier triaging, remediation, and reporting

## Data Migration from Current On-Prem Setup

The following data will be migrated from the existing on-premises setup:

- All old scan details and application history
- User information and console platform credentials
- List of previously scanned applications
- OSS and build policies configurations
- Alert settings
- Organization settings
- All other details present in Keycloak service and Cdefense database

## Sensitive Information Handling

### Existing User Credentials

A mandatory force reset password will be provided to users for their first login in the hybrid setup to rotate credentials.

### Scan Data

All client data will be stored in a dedicated database instance allocated specifically for the client, with proper encryption in place to keep data safe and protected.