# License Cache SCA — Deployment Guide

## Overview

This document describes how to deploy the `licensecachesca` service on a Kubernetes cluster. The service runs a combined gRPC + Redis container used for license cache lookups in the hybrid SCA pipeline.

---

## Prerequisites

Before deploying, ensure the following are in place:

### 1. Kubernetes Cluster Access
- `kubectl` is configured and pointing to the target cluster.
- You have sufficient RBAC permissions to create Namespaces, Deployments, Services, and PersistentVolumeClaims.

### 2. Image Pull Secret
- A Kubernetes secret named `image-secret` must exist in the `default` namespace with credentials to pull from the `cdefense` container registry.

```bash
kubectl create secret docker-registry image-secret \
  --docker-server=<registry-url> \
  --docker-username=<username> \
  --docker-password=<password> \
  --namespace=default
```

### 3. EBS Permissions for PVC (AWS EKS)

> **Required if using the PersistentVolumeClaim (PVC) for Redis data persistence.**

The PVC uses `storageClassName: gp2` (or `gp3`), which provisions an **AWS EBS volume**. For this to work, the node/service account must have the necessary EBS permissions.

**Option A — IAM Role for Service Account (IRSA) (recommended):**
- Attach the `AmazonEBSCSIDriverPolicy` managed policy to the IRSA role associated with the EBS CSI driver.
- Ensure the **EBS CSI Driver** add-on is installed on your EKS cluster:

```bash
aws eks create-addon \
  --cluster-name <your-cluster-name> \
  --addon-name aws-ebs-csi-driver \
  --region <your-region>
```

**Option B — Node IAM Role:**
Attach the following policy to the EC2 node instance role:

```json
{
  "Effect": "Allow",
  "Action": [
    "ec2:CreateVolume",
    "ec2:AttachVolume",
    "ec2:DetachVolume",
    "ec2:DeleteVolume",
    "ec2:DescribeVolumes",
    "ec2:DescribeVolumeStatus",
    "ec2:ModifyVolume",
    "ec2:CreateTags"
  ],
  "Resource": "*"
}
```

---

## Deployment Steps

### 1. Apply the manifest

```bash
kubectl apply -f license-cache.yaml
```

This creates:
- `Namespace`: `default`
- `PersistentVolumeClaim`: `licensecachesca-redis-pvc` (20Gi, ReadWriteOnce)
- `Deployment`: `licensecachesca` (1 replica)
- `Service`: `licensecachesca` (ClusterIP)

### 2. Verify the deployment

```bash
kubectl get pods -n default -l app=licensecachesca
kubectl get svc -n default licensecachesca
kubectl get pvc -n default licensecachesca-redis-pvc
```

### 3. Check logs

```bash
kubectl logs -n default -l app=licensecachesca
```

---

## Service Ports

| Port  | Protocol | Description     |
|-------|----------|-----------------|
| 50051 | gRPC     | License cache   |
| 6379  | TCP      | Redis           |

---

## Resource Limits

| Resource | Request | Limit  |
|----------|---------|--------|
| Memory   | 250Mi   | 320Mi  |
| CPU      | 25m     | —      |

---

## Health Checks

Both liveness and readiness probes verify:
- Redis is responding: `redis-cli ping` returns `PONG`
- gRPC port 50051 is open: `nc -z localhost 50051`

---

## Teardown

```bash
kubectl delete -f license-cache.yaml
```

> **Note:** Deleting the manifest does **not** automatically delete the EBS volume backing the PVC. To fully clean up, also delete the PVC:

```bash
kubectl delete pvc licensecachesca-redis-pvc -n default
```
