# EKS Testing Infrastructure — eBPF Observability Agent

Production-grade Terraform module that provisions a 2-node EKS cluster for
testing the eBPF observability agent using **systemd** (not DaemonSet).

The eBPF agent binary + BPF objects are uploaded to **S3** and pulled by each
node at boot via `user-data`. Prometheus & Grafana run **locally** via
`docker-compose` and scrape the nodes via `kubectl port-forward`.

---

## Architecture

```
LOCAL MACHINE
  docker-compose (Prometheus :9090, Grafana :3000)
       ↑ scrapes via kubectl port-forward
       |
AWS EKS Cluster (2 × t3.small, AL2023 — kernel 6.1, cgroup v2)
  Node 1  systemd: ebpf-observer.service :8080/metrics
  Node 2  systemd: ebpf-observer.service :8080/metrics
       ↑ pulls artifacts at boot
       |
  S3 Bucket (observer binary + *.o BPF files)
```

---

## Cost Estimate

| Resource | Rate | 24hr cost |
|---|---|---|
| EKS control plane | $0.10/hr | $2.40 |
| 2 × t3.small | $0.00/hr (Free Tier) | $0.00 |
| NAT Gateway | $0.045/hr | $1.08 |
| S3 storage | ~$0.023/GB/month | < $0.01 |
| **Total** | | **~$3.48/day** |

> ⚠️ **Always run `terraform destroy` when done testing.**

---

## Prerequisites

| Tool | Version | Install |
|---|---|---|
| Terraform | ≥ 1.6 | `brew install terraform` or [tfenv](https://github.com/tfutils/tfenv) |
| AWS CLI v2 | ≥ 2.15 | [docs](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html) |
| kubectl | ≥ 1.28 | `brew install kubectl` |
| Go | ≥ 1.22 | [go.dev](https://go.dev/dl/) |
| clang / llvm | ≥ 14 | `sudo apt install clang llvm libbpf-dev` |
| make | any | pre-installed |

**AWS permissions required** (your IAM user/role must have):
- `eks:*`, `ec2:*`, `iam:*`, `s3:*`, `cloudwatch:*`
- Or attach `AdministratorAccess` for testing (not for production)

Verify your credentials work:
```bash
aws sts get-caller-identity
```

---

## Step-by-Step Usage

### 1. Configure (optional)

Create `deploy/terraform/terraform.tfvars` to override defaults:

```hcl
# terraform.tfvars — customize for your environment
aws_region         = "us-east-1"
cluster_name       = "ebpf-observer-test"
node_instance_type = "t3.small"
node_desired_count = 2

# Replace with your actual email to receive billing alerts
# (edit the aws_budgets_budget resource in eks.tf)
```

### 2. Provision infrastructure

```bash
cd deploy/terraform

# Download providers
terraform init

# Preview what will be created (~30 resources)
terraform plan -out=tfplan

# Apply — EKS takes ~15 minutes to provision
terraform apply tfplan
```

> **Note:** EKS cluster creation takes 10-15 minutes. Node group creation
> takes another 3-5 minutes. Be patient.

After apply completes, Terraform prints:
- `cluster_name` — EKS cluster name
- `s3_bucket_name` — artifact bucket name
- `kubeconfig_command` — copy/paste to configure kubectl
- `cost_reminder` — a friendly reminder to destroy when done

### 3. Configure kubectl

```bash
# Copy/paste the kubeconfig_command from terraform output, or:
make eks-kubeconfig

# Verify nodes are Ready
kubectl get nodes
# NAME                         STATUS   ROLES    AGE   VERSION
# ip-10-0-10-xxx.ec2.internal  Ready    <none>   3m    v1.30.x
# ip-10-0-11-xxx.ec2.internal  Ready    <none>   3m    v1.30.x
```

### 4. Build and upload artifacts

From the **project root** (not the terraform directory):

```bash
# Build the observer binary + all eBPF .o objects
make build

# Upload to S3 (bucket name auto-read from terraform output)
make eks-push
```

This uploads:
- `observer` binary → `s3://<bucket>/releases/latest/observer`
- `ebpf/*.o` objects → `s3://<bucket>/releases/latest/ebpf/`
- `deploy/systemd/` files → `s3://<bucket>/releases/latest/systemd/`
- `SHA256SUMS` manifest → `s3://<bucket>/releases/latest/SHA256SUMS`

### 5. Trigger node installation

The nodes run the bootstrap script at boot. If nodes already booted before
you pushed artifacts, trigger a re-install via SSM:

```bash
make eks-refresh
```

Or check if the bootstrap already ran (look for the `ebpf-observer/bootstrap` tag):
```bash
make eks-status
```

### 6. Start local monitoring

In a **dedicated terminal** (keep it open):
```bash
# Port-forward both nodes' :8080 to local :8081 and :8082
make eks-port-forward
```

In another terminal:
```bash
# Start Prometheus + Grafana locally
make monitoring-up
```

Open dashboards:
- **Prometheus**: http://localhost:9090 → Status → Targets
  - You should see `ebpf-observer-eks-node1` and `ebpf-observer-eks-node2` as UP
- **Grafana**: http://localhost:3000 (admin/admin)

### 7. View agent logs

```bash
# Stream systemd logs from both nodes
make eks-logs
```

### 8. Deploy a test workload

```bash
# Create a simple nginx pod to generate container metrics
kubectl run nginx-test --image=nginx --restart=Never
kubectl run redis-test --image=redis --restart=Never

# Watch metrics flow in
# Open Grafana → eBPF Observer dashboard → Container view
```

### 9. Destroy everything

```bash
# From project root
make eks-destroy

# Or manually
cd deploy/terraform
terraform destroy
```

---

## File Structure

```
deploy/terraform/
├── versions.tf          # Terraform + provider version pins
├── variables.tf         # All tunable inputs with defaults
├── main.tf              # Provider, locals, random suffix, data sources
├── vpc.tf               # VPC, subnets, IGW, NAT GW, security groups
├── iam.tf               # EKS cluster role, node role, S3 read policy, OIDC
├── s3.tf                # Artifact bucket + VPC Gateway endpoint
├── eks.tf               # EKS cluster, addons, launch template, node group, alarms
├── outputs.tf           # All outputs including convenience commands
├── terraform.tfvars     # (gitignored) your local overrides
└── userdata/
    └── install.sh       # Node bootstrap: S3 pull → systemd install
```

---

## Troubleshooting

### Nodes not Ready after 10 minutes

```bash
kubectl describe nodes
kubectl get events --sort-by=.lastTimestamp -A
```

### eBPF agent not starting on a node

1. Get the node's instance ID:
   ```bash
   kubectl get nodes -o wide
   aws ec2 describe-instances --filters "Name=private-ip-address,Values=<node-ip>" \
     --query 'Reservations[].Instances[].InstanceId' --output text
   ```

2. Open an SSM session:
   ```bash
   aws ssm start-session --target <instance-id> --region us-east-1
   ```

3. Inside the session:
   ```bash
   # Check bootstrap log
   cat /var/log/ebpf-observer-install.log

   # Check service status
   systemctl status ebpf-observer

   # Live logs
   journalctl -u ebpf-observer -f
   ```

### Metrics not reaching local Prometheus

```bash
# Check port-forward is running
ps aux | grep 'kubectl port-forward'

# Manually test
curl http://localhost:8081/metrics | head -5
curl http://localhost:8082/metrics | head -5

# Check Prometheus targets
open http://localhost:9090/targets
```

### Kernel too old / no BTF support

```bash
# On a node (via SSM):
uname -r          # Should be 6.1+
ls /sys/kernel/btf/vmlinux  # Should exist
```

---

## Security Notes

- **No SSH keys** — access via SSM Session Manager only
- **IMDSv2 enforced** — `http_tokens = required` in launch template
- **Nodes in private subnets** — no public IPs on worker nodes
- **S3 bucket**: public access blocked, HTTPS-only policy, AES256 encryption
- **Minimal IAM**: node role has only the permissions needed (S3 read-only on artifact bucket)
- **Metrics port** (8080): exposed via Security Group rule to `0.0.0.0/0` by default — **narrow this to your dev IP** in `terraform.tfvars`:
  ```hcl
  prometheus_scrape_cidrs = ["YOUR.IP.ADDRESS/32"]
  ```
