## Resources Created by eksctl

When the cluster creation completes, the following AWS resources will be created:

### 1. EKS Control Plane
- Managed Kubernetes master nodes
- API server endpoint
- etcd cluster for state storage

### 2. VPC and Networking (Counts will get adjusted according to the CIDR range automatically)
- **VPC** with CIDR `10.20.0.0/16` 
- **2 Public Subnets** (for load balancers and NAT Gateway)
- **2 Private Subnets** (for worker nodes)
- **Internet Gateway** (for public subnet internet access)
- **NAT Gateway** (for private subnet outbound internet access)
- **Route Tables** (public and private routing)
- **Security Groups** (cluster and node security groups)

### 3. EC2 Compute Resources
- **1 t3.medium EC2 instance** (managed worker node)
- **Encrypted EBS volumes** attached to worker nodes
- **Auto Scaling Group** (min: 1, max: 2 nodes)
- **Launch Template** for node configuration

### 4. IAM Roles and Policies
- **EKS Cluster Service Role** - Allows EKS to manage AWS resources
- **Node Group IAM Role** - Permissions for worker nodes
- **Instance Profile** - Attached to EC2 worker nodes
- **Managed Policies**:
  - AmazonEKSClusterPolicy
  - AmazonEKSWorkerNodePolicy
  - AmazonEC2ContainerRegistryReadOnly
  - AmazonEKS_CNI_Policy

### 5. CloudFormation Stacks
- `eksctl-cdefense-hybrid-cluster` - Main cluster infrastructure
- `eksctl-cdefense-hybrid-nodegroup-cdefense-node` - Node group resources

### 6. EKS Add-ons
- **Amazon VPC CNI** - Pod networking
- **CoreDNS** - Cluster DNS resolution
- **kube-proxy** - Network routing rules
