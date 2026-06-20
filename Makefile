# =============================================================================
# SelfHeal-CP — Makefile
# Self-Healing Kubernetes Control Plane
# =============================================================================
# Components:
#   agent      — eBPF DaemonSet agent (per-node kernel observer)
#   analyzer   — Heuristics engine (anomaly detection)
#   controller — Kubernetes controller (healing actions)
#   observer   — Standalone eBPF observer (debugging/dev)
#   tui        — Terminal UI
#
# eBPF probes:
#   ebpf/probes/   — Core self-heal probes (cpu, memory, io, network, syscall)
#   ebpf/security/ — Security telemetry (lineage, exec, dns, privesc, escape)
# =============================================================================

# ─── Toolchain ────────────────────────────────────────────────────────────────
BPF_CLANG     := clang
BPF_CFLAGS    := -O2 -g -target bpf \
                 -I/usr/include/$(shell uname -m)-linux-gnu \
                 -D__TARGET_ARCH_x86

GO            := go
PROTOC        := protoc

# ─── Binary targets ───────────────────────────────────────────────────────────
AGENT_BIN        := bin/agent
ANALYZER_BIN     := bin/analyzer
CONTROLLER_BIN   := bin/controller
OBSERVER_BIN     := bin/observer
TUI_BIN          := bin/tui

AGENT_ENTRY      := ./cmd/agent
ANALYZER_ENTRY   := ./cmd/analyzer
CONTROLLER_ENTRY := ./cmd/controller
OBSERVER_ENTRY   := ./cmd/observer
TUI_ENTRY        := ./cmd/tui

# ─── eBPF probe sources & objects ─────────────────────────────────────────────
# Core self-healing probes (Phase 1)
BPF_SRC_CPU    := ebpf/probes/cpu.c
BPF_OBJ_CPU    := ebpf/probes/cpu.o

BPF_SRC_MEM    := ebpf/probes/memory.c
BPF_OBJ_MEM    := ebpf/probes/memory.o

BPF_SRC_IO     := ebpf/probes/io.c
BPF_OBJ_IO     := ebpf/probes/io.o

BPF_SRC_NET    := ebpf/probes/network.c
BPF_OBJ_NET    := ebpf/probes/network.o

BPF_SRC_SYS    := ebpf/probes/syscall.c
BPF_OBJ_SYS    := ebpf/probes/syscall.o

CORE_BPF_OBJS  := $(BPF_OBJ_CPU) $(BPF_OBJ_MEM) $(BPF_OBJ_IO) $(BPF_OBJ_NET) $(BPF_OBJ_SYS)

# Security telemetry probes (Phase 5 bonus)
BPF_SRC_LINEAGE  := ebpf/security/lineage.c
BPF_OBJ_LINEAGE  := ebpf/security/lineage.o

BPF_SRC_EXEC     := ebpf/security/exec.c
BPF_OBJ_EXEC     := ebpf/security/exec.o

BPF_SRC_DNS      := ebpf/security/dns.c
BPF_OBJ_DNS      := ebpf/security/dns.o

BPF_SRC_PRIVESC  := ebpf/security/privesc.c
BPF_OBJ_PRIVESC  := ebpf/security/privesc.o

BPF_SRC_ESCAPE   := ebpf/security/escape.c
BPF_OBJ_ESCAPE   := ebpf/security/escape.o

SECURITY_BPF_OBJS := $(BPF_OBJ_LINEAGE) $(BPF_OBJ_EXEC) $(BPF_OBJ_DNS) \
                     $(BPF_OBJ_PRIVESC) $(BPF_OBJ_ESCAPE)

# BPF pin path for cross-module map sharing
BPF_PIN_PATH     := /sys/fs/bpf/selfheal

# ─── Proto definitions ─────────────────────────────────────────────────────────
PROTO_DIR    := proto
PROTO_OUT    := internal/gen/proto
PROTO_FILES  := $(wildcard $(PROTO_DIR)/*.proto)

# ─── Phony targets ─────────────────────────────────────────────────────────────
.PHONY: all build \
        bpf bpf-core bpf-security bpf-skeleton \
        agent-build analyzer-build controller-build observer-build tui-build \
        run-agent run-agent-k8s run-observer run-observer-k8s \
        run-observer-security run-tui run-tui-demo \
        proto \
        test test-unit test-integration test-e2e \
        dev-up dev-down dev-logs \
        k8s-deploy k8s-undeploy k8s-restart k8s-dashboard \
        monitoring-up monitoring-down monitoring-logs monitoring-prom-only \
        docker-build-agent docker-build-analyzer docker-build-controller \
        eks-push eks-kubeconfig eks-port-forward eks-status eks-logs eks-refresh eks-destroy \
        install uninstall \
        systemd-start systemd-stop systemd-status systemd-logs \
        pin-path clean fmt lint help

# ─── Default target ───────────────────────────────────────────────────────────
all: bpf-core agent-build analyzer-build controller-build
	@echo ""
	@echo "✅ SelfHeal-CP build complete"
	@echo "   Binaries: $(AGENT_BIN)  $(ANALYZER_BIN)  $(CONTROLLER_BIN)"

build: all

# =============================================================================
# eBPF Compilation
# =============================================================================

# Compile all probes (core + security)
bpf: bpf-core bpf-security
	@echo "✅ All eBPF probes compiled"

# Core self-heal probes only
bpf-core: $(CORE_BPF_OBJS)
	@echo "✅ Core eBPF probes compiled (cpu, memory, io, network, syscall)"

# Security telemetry probes
bpf-security: $(SECURITY_BPF_OBJS)
	@echo "✅ Security eBPF probes compiled (lineage, exec, dns, privesc, escape)"

$(BPF_OBJ_CPU): $(BPF_SRC_CPU)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "  ✓ cpu.o"

$(BPF_OBJ_MEM): $(BPF_SRC_MEM)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "  ✓ memory.o"

$(BPF_OBJ_IO): $(BPF_SRC_IO)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "  ✓ io.o"

$(BPF_OBJ_NET): $(BPF_SRC_NET)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "  ✓ network.o"

$(BPF_OBJ_SYS): $(BPF_SRC_SYS)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "  ✓ syscall.o"

$(BPF_OBJ_LINEAGE): $(BPF_SRC_LINEAGE)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "  ✓ lineage.o"

$(BPF_OBJ_EXEC): $(BPF_SRC_EXEC)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "  ✓ exec.o"

$(BPF_OBJ_DNS): $(BPF_SRC_DNS)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "  ✓ dns.o"

$(BPF_OBJ_PRIVESC): $(BPF_SRC_PRIVESC)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "  ✓ privesc.o"

$(BPF_OBJ_ESCAPE): $(BPF_SRC_ESCAPE)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "  ✓ escape.o"

# Generate BTF skeletons for CO-RE (requires bpftool)
bpf-skeleton: bpf-core
	@echo "Generating BTF skeletons..."
	@mkdir -p internal/ebpf/gen
	bpftool gen skeleton $(BPF_OBJ_CPU)  > internal/ebpf/gen/cpu.skel.h
	bpftool gen skeleton $(BPF_OBJ_MEM)  > internal/ebpf/gen/memory.skel.h
	bpftool gen skeleton $(BPF_OBJ_IO)   > internal/ebpf/gen/io.skel.h
	bpftool gen skeleton $(BPF_OBJ_NET)  > internal/ebpf/gen/network.skel.h
	bpftool gen skeleton $(BPF_OBJ_SYS)  > internal/ebpf/gen/syscall.skel.h
	@echo "✅ BTF skeletons generated in internal/ebpf/gen/"

# Ensure BPF pin path exists (run as root before agent starts)
pin-path:
	@sudo mkdir -p $(BPF_PIN_PATH)
	@echo "✅ BPF pin path: $(BPF_PIN_PATH)"

# =============================================================================
# Protobuf Generation
# =============================================================================

proto: $(PROTO_FILES)
	@echo "Generating protobuf Go bindings..."
	@mkdir -p $(PROTO_OUT)
	$(PROTOC) \
		--go_out=$(PROTO_OUT) \
		--go_opt=paths=source_relative \
		--proto_path=$(PROTO_DIR) \
		$(PROTO_FILES)
	@echo "✅ Protobuf bindings generated in $(PROTO_OUT)/"

# =============================================================================
# Go Builds
# =============================================================================

# eBPF Agent (DaemonSet — per node)
agent-build: bpf-core
	@mkdir -p bin
	$(GO) mod tidy
	$(GO) build -o $(AGENT_BIN) $(AGENT_ENTRY)
	@echo "✅ Agent binary: $(AGENT_BIN)"

# Analyzer (Heuristics Engine)
analyzer-build:
	@mkdir -p bin
	$(GO) mod tidy
	$(GO) build -o $(ANALYZER_BIN) $(ANALYZER_ENTRY)
	@echo "✅ Analyzer binary: $(ANALYZER_BIN)"

# Kubernetes Controller
controller-build:
	@mkdir -p bin
	$(GO) mod tidy
	$(GO) build -o $(CONTROLLER_BIN) $(CONTROLLER_ENTRY)
	@echo "✅ Controller binary: $(CONTROLLER_BIN)"

# Standalone observer (dev/debug tool)
observer-build: bpf
	@mkdir -p bin
	$(GO) build -o $(OBSERVER_BIN) $(OBSERVER_ENTRY)
	@echo "✅ Observer binary: $(OBSERVER_BIN)"

# Terminal UI
tui-build: bpf
	@mkdir -p bin
	$(GO) build -o $(TUI_BIN) $(TUI_ENTRY)
	@echo "✅ TUI binary: $(TUI_BIN)"

# =============================================================================
# Run Targets
# =============================================================================

# Run agent (requires root + cgroup v2)
run-agent: agent-build
	sudo mkdir -p $(BPF_PIN_PATH)
	sudo $(AGENT_BIN) \
		--cpu-bpf  $(BPF_OBJ_CPU) \
		--mem-bpf  $(BPF_OBJ_MEM) \
		--io-bpf   $(BPF_OBJ_IO) \
		--net-bpf  $(BPF_OBJ_NET) \
		--sys-bpf  $(BPF_OBJ_SYS) \
		--kubernetes

# Run agent in Kubernetes mode with all probes
run-agent-k8s: agent-build
	sudo mkdir -p $(BPF_PIN_PATH)
	sudo $(AGENT_BIN) \
		--cpu-bpf     $(BPF_OBJ_CPU) \
		--mem-bpf     $(BPF_OBJ_MEM) \
		--io-bpf      $(BPF_OBJ_IO) \
		--net-bpf     $(BPF_OBJ_NET) \
		--sys-bpf     $(BPF_OBJ_SYS) \
		--lineage-bpf $(BPF_OBJ_LINEAGE) \
		--exec-bpf    $(BPF_OBJ_EXEC) \
		--dns-bpf     $(BPF_OBJ_DNS) \
		--privesc-bpf $(BPF_OBJ_PRIVESC) \
		--escape-bpf  $(BPF_OBJ_ESCAPE) \
		--kubernetes \
		--show-security

# Standalone observer (local dev — shows all cgroups)
run-observer: observer-build
	sudo $(OBSERVER_BIN) \
		--cpu-bpf $(BPF_OBJ_CPU) \
		--mem-bpf $(BPF_OBJ_MEM) \
		--io-bpf  $(BPF_OBJ_IO) \
		--net-bpf $(BPF_OBJ_NET) \
		--sys-bpf $(BPF_OBJ_SYS) \
		--containers-only \
		--rich-mem

# Observer with security probes
run-observer-security: observer-build
	sudo mkdir -p $(BPF_PIN_PATH)
	sudo $(OBSERVER_BIN) \
		--cpu-bpf     $(BPF_OBJ_CPU) \
		--mem-bpf     $(BPF_OBJ_MEM) \
		--io-bpf      $(BPF_OBJ_IO) \
		--net-bpf     $(BPF_OBJ_NET) \
		--sys-bpf     $(BPF_OBJ_SYS) \
		--lineage-bpf $(BPF_OBJ_LINEAGE) \
		--exec-bpf    $(BPF_OBJ_EXEC) \
		--dns-bpf     $(BPF_OBJ_DNS) \
		--privesc-bpf $(BPF_OBJ_PRIVESC) \
		--escape-bpf  $(BPF_OBJ_ESCAPE) \
		--containers-only \
		--show-security \
		--rich-mem

# TUI with live BPF
run-tui: tui-build
	sudo $(TUI_BIN) \
		--cpu-bpf     $(BPF_OBJ_CPU) \
		--mem-bpf     $(BPF_OBJ_MEM) \
		--io-bpf      $(BPF_OBJ_IO) \
		--net-bpf     $(BPF_OBJ_NET) \
		--sys-bpf     $(BPF_OBJ_SYS) \
		--lineage-bpf $(BPF_OBJ_LINEAGE) \
		--exec-bpf    $(BPF_OBJ_EXEC) \
		--dns-bpf     $(BPF_OBJ_DNS) \
		--privesc-bpf $(BPF_OBJ_PRIVESC) \
		--escape-bpf  $(BPF_OBJ_ESCAPE) \
		--containers-only \
		--rich-mem

# Demo TUI — no root required
run-tui-demo:
	$(GO) run $(TUI_ENTRY) --demo

# =============================================================================
# Tests
# =============================================================================

test: test-unit
	@echo "✅ All tests passed"

# Unit tests (no BPF, no root required)
test-unit:
	$(GO) test -v -count=1 -race ./tests/unit/... ./internal/...
	@echo "✅ Unit tests passed"

# Integration tests (requires running NATS)
test-integration: dev-up
	$(GO) test -v -count=1 -timeout 120s ./tests/integration/...
	@echo "✅ Integration tests passed"

# End-to-end tests (requires full k8s cluster)
test-e2e:
	$(GO) test -v -count=1 -timeout 300s ./tests/e2e/...
	@echo "✅ E2E tests passed"

# =============================================================================
# Dev Environment (NATS + Prometheus + Grafana)
# =============================================================================

dev-up:
	docker compose -f config/dev/docker-compose.yml up -d
	@echo ""
	@echo "  Dev stack started:"
	@echo "    NATS          → nats://localhost:4222"
	@echo "    NATS Monitor  → http://localhost:8222"
	@echo "    Prometheus    → http://localhost:9090"
	@echo "    Grafana       → http://localhost:3000  (admin/admin)"
	@echo ""

dev-down:
	docker compose -f config/dev/docker-compose.yml down

dev-logs:
	docker compose -f config/dev/docker-compose.yml logs -f

# =============================================================================
# Monitoring Stack (Prometheus + Grafana via docker-compose)
# =============================================================================

monitoring-up:
	docker compose up -d
	@echo ""
	@echo "  Monitoring stack started:"
	@echo "    Observer metrics → http://localhost:8080/metrics"
	@echo "    Prometheus       → http://localhost:9090"
	@echo "    Grafana          → http://localhost:3000  (admin/admin)"

monitoring-down:
	docker compose down

monitoring-logs:
	docker compose logs -f

monitoring-prom-only:
	docker compose up -d prometheus
	@echo "  Prometheus scraping at http://localhost:9090"

# =============================================================================
# Docker Builds
# =============================================================================

docker-build-agent:
	docker build -t selfheal-agent:latest -f deploy/docker/Dockerfile.agent .

docker-build-analyzer:
	docker build -t selfheal-analyzer:latest -f deploy/docker/Dockerfile.analyzer .

docker-build-controller:
	docker build -t selfheal-controller:v3 -f deploy/docker/Dockerfile.controller .

# Legacy observer image
docker-build:
	docker build -t ebpf-observer:latest .

# =============================================================================
# Kubernetes Deployment
# =============================================================================

k8s-deploy: docker-build-agent docker-build-analyzer docker-build-controller
	@echo "Loading images into minikube..."
	minikube image load selfheal-agent:latest || true
	minikube image load selfheal-analyzer:latest || true
	minikube image load selfheal-controller:v3 || true
	@echo "Installing Prometheus Operator..."
	helm repo add prometheus-community https://prometheus-community.github.io/helm-charts 2>/dev/null || true
	helm repo update
	helm upgrade --install prometheus prometheus-community/kube-prometheus-stack \
		--namespace monitoring --create-namespace \
		-f deploy/k8s/prometheus-values.yaml
	@echo "Applying SelfHeal manifests..."
	kubectl apply -f deploy/k8s/serviceaccount.yaml
	kubectl apply -f deploy/k8s/rbac.yaml
	kubectl apply -f deploy/k8s/service.yaml
	kubectl apply -f deploy/k8s/nats.yaml
	kubectl create configmap selfheal-config \
		--from-file=rules.yaml=config/rules.yaml \
		--from-file=guardrails.yaml=config/guardrails.yaml \
		-n kube-system --dry-run=client -o yaml | kubectl apply -f -
	kubectl apply -f deploy/k8s/daemonset.yaml
	kubectl apply -f deploy/k8s/deployment.yaml
	kubectl apply -f deploy/k8s/servicemonitor.yaml -n monitoring
	kubectl apply -f deploy/k8s/grafana-dashboard-configmap.yaml -n monitoring
	@echo "✅ SelfHeal-CP deployed to Kubernetes"

k8s-undeploy:
	-kubectl delete -f deploy/k8s/deployment.yaml 2>/dev/null || true
	-kubectl delete -f deploy/k8s/daemonset.yaml 2>/dev/null || true
	-kubectl delete -f deploy/k8s/servicemonitor.yaml -n monitoring 2>/dev/null || true
	-kubectl delete -f deploy/k8s/grafana-dashboard-configmap.yaml -n monitoring 2>/dev/null || true
	-kubectl delete -f deploy/k8s/service.yaml 2>/dev/null || true
	-kubectl delete -f deploy/k8s/rbac.yaml 2>/dev/null || true
	-kubectl delete -f deploy/k8s/serviceaccount.yaml 2>/dev/null || true
	-helm uninstall prometheus -n monitoring 2>/dev/null || true
	@echo "✅ SelfHeal-CP removed from Kubernetes"

k8s-restart:
	minikube image load selfheal-agent:latest
	kubectl rollout restart daemonset selfheal-agent -n kube-system
	kubectl rollout status daemonset selfheal-agent -n kube-system

k8s-dashboard:
	@echo "------------------------------------------------------------"
	@echo "  Grafana Credentials:"
	@echo "    Username: admin"
	@echo "    Password: $$(kubectl get secret --namespace monitoring prometheus-grafana -o jsonpath='{.data.admin-password}' | base64 --decode)"
	@echo "------------------------------------------------------------"
	kubectl port-forward svc/prometheus-grafana -n monitoring 3000:80

# =============================================================================
# EKS / S3 Targets
# =============================================================================
#
# Prerequisites:
#   - AWS CLI configured  (aws sts get-caller-identity must work)
#   - Terraform applied   (cd deploy/terraform && terraform apply)
#   - kubectl configured  (make eks-kubeconfig)
#
# Workflow:
#   1. make eks-kubeconfig     → configure kubectl
#   2. make eks-push           → build + upload to S3
#   3. make eks-refresh        → re-install on nodes via SSM
#   4. make eks-port-forward   → background port-forward
#   5. make dev-up             → start local Prometheus + Grafana
#   6. make eks-destroy        → tear down when done

TF_DIR         := deploy/terraform
AWS_REGION     ?= us-east-1
S3_BUCKET      ?= $(shell cd $(TF_DIR) && terraform output -raw s3_bucket_name 2>/dev/null || echo "")
CLUSTER_NAME   ?= $(shell cd $(TF_DIR) && terraform output -raw cluster_name 2>/dev/null || echo "selfheal-cp-test")
S3_PREFIX      := releases/latest
SHA256SUMS     := SHA256SUMS

eks-push: agent-build
	@if [ -z "$(S3_BUCKET)" ]; then \
	  echo "❌ S3_BUCKET not set. Run 'cd deploy/terraform && terraform apply' first."; exit 1; fi
	@echo "Generating SHA256SUMS..."
	@sha256sum $(AGENT_BIN) ebpf/probes/*.o > /tmp/$(SHA256SUMS)
	@echo "Uploading to s3://$(S3_BUCKET)/$(S3_PREFIX)/"
	aws s3 cp $(AGENT_BIN) \
	  s3://$(S3_BUCKET)/$(S3_PREFIX)/agent \
	  --region $(AWS_REGION) --sse AES256
	aws s3 sync ebpf/probes/ \
	  s3://$(S3_BUCKET)/$(S3_PREFIX)/ebpf/probes/ \
	  --region $(AWS_REGION) --sse AES256 \
	  --exclude "*" --include "*.o"
	aws s3 sync deploy/systemd/ \
	  s3://$(S3_BUCKET)/$(S3_PREFIX)/systemd/ \
	  --region $(AWS_REGION) --sse AES256
	aws s3 cp /tmp/$(SHA256SUMS) \
	  s3://$(S3_BUCKET)/$(S3_PREFIX)/$(SHA256SUMS) \
	  --region $(AWS_REGION) --sse AES256
	@echo "✅ Artifacts uploaded to s3://$(S3_BUCKET)/$(S3_PREFIX)/"

eks-kubeconfig:
	aws eks update-kubeconfig --region $(AWS_REGION) --name $(CLUSTER_NAME)
	@echo "✅ kubectl configured. Test with: kubectl get nodes"

eks-port-forward:
	@PODS=$$(kubectl get pods -n kube-system -l k8s-app=aws-node -o jsonpath='{.items[*].metadata.name}'); \
	METRICS_PORT=8080; LOCAL_PORT=8081; PIDS=""; \
	for POD in $$PODS; do \
	  NODE=$$(kubectl get pod -n kube-system $$POD -o jsonpath='{.spec.nodeName}'); \
	  echo "  Port-forwarding $$NODE → localhost:$$LOCAL_PORT"; \
	  kubectl port-forward -n kube-system $$POD $$LOCAL_PORT:$$METRICS_PORT & \
	  PIDS="$$PIDS $$!"; \
	  LOCAL_PORT=$$((LOCAL_PORT + 1)); \
	done; \
	echo "  Press Ctrl-C to stop."; \
	trap 'kill $$PIDS 2>/dev/null' INT TERM; \
	wait $$PIDS

eks-status:
	@INSTANCES=$$(aws ec2 describe-instances \
	  --region $(AWS_REGION) \
	  --filters \
	    "Name=tag:kubernetes.io/cluster/$(CLUSTER_NAME),Values=owned" \
	    "Name=instance-state-name,Values=running" \
	  --query 'Reservations[].Instances[].InstanceId' \
	  --output text); \
	for ID in $$INSTANCES; do \
	  echo "── Node: $$ID ────────────────────────────────────────"; \
	  CMD_ID=$$(aws ssm send-command \
	    --region $(AWS_REGION) --instance-ids $$ID \
	    --document-name AWS-RunShellScript \
	    --parameters 'commands=["systemctl status selfheal-agent --no-pager -l"]' \
	    --query 'Command.CommandId' --output text); \
	  sleep 5; \
	  aws ssm get-command-invocation \
	    --region $(AWS_REGION) --command-id $$CMD_ID --instance-id $$ID \
	    --query 'StandardOutputContent' --output text; \
	done

eks-logs:
	@INSTANCES=$$(aws ec2 describe-instances \
	  --region $(AWS_REGION) \
	  --filters \
	    "Name=tag:kubernetes.io/cluster/$(CLUSTER_NAME),Values=owned" \
	    "Name=instance-state-name,Values=running" \
	  --query 'Reservations[].Instances[].InstanceId' \
	  --output text); \
	for ID in $$INSTANCES; do \
	  echo "── Node: $$ID logs ──────────────────────────────────"; \
	  CMD_ID=$$(aws ssm send-command \
	    --region $(AWS_REGION) --instance-ids $$ID \
	    --document-name AWS-RunShellScript \
	    --parameters 'commands=["journalctl -u selfheal-agent -n 100 --no-pager"]' \
	    --query 'Command.CommandId' --output text); \
	  sleep 5; \
	  aws ssm get-command-invocation \
	    --region $(AWS_REGION) --command-id $$CMD_ID --instance-id $$ID \
	    --query 'StandardOutputContent' --output text; \
	done

eks-refresh:
	@if [ -z "$(S3_BUCKET)" ]; then \
	  echo "❌ S3_BUCKET not set."; exit 1; fi
	@INSTANCES=$$(aws ec2 describe-instances \
	  --region $(AWS_REGION) \
	  --filters \
	    "Name=tag:kubernetes.io/cluster/$(CLUSTER_NAME),Values=owned" \
	    "Name=instance-state-name,Values=running" \
	  --query 'Reservations[].Instances[].InstanceId' \
	  --output text); \
	for ID in $$INSTANCES; do \
	  echo "  Refreshing node $$ID..."; \
	  aws ssm send-command \
	    --region $(AWS_REGION) --instance-ids $$ID \
	    --document-name AWS-RunShellScript \
	    --parameters "commands=[\
	      \"set -e\",\
	      \"aws s3 cp s3://$(S3_BUCKET)/$(S3_PREFIX)/agent /usr/local/bin/selfheal-agent --region $(AWS_REGION)\",\
	      \"chmod 755 /usr/local/bin/selfheal-agent\",\
	      \"aws s3 sync s3://$(S3_BUCKET)/$(S3_PREFIX)/ebpf/ /usr/local/share/selfheal/ --region $(AWS_REGION) --exclude '*' --include '*.o'\",\
	      \"systemctl daemon-reload\",\
	      \"systemctl restart selfheal-agent\",\
	      \"sleep 3\",\
	      \"systemctl is-active selfheal-agent && echo OK || echo FAILED\"\
	    ]" \
	    --query 'Command.CommandId' --output text; \
	done
	@echo "✅ Refresh dispatched. Check: make eks-status"

eks-destroy:
	@echo "⚠️  This will DESTROY the EKS cluster, VPC, and S3 bucket."
	@read -p "Type 'yes' to confirm: " CONFIRM; \
	if [ "$$CONFIRM" = "yes" ]; then \
	  cd $(TF_DIR) && terraform destroy; \
	  echo "✅ All infrastructure destroyed."; \
	else \
	  echo "Aborted."; \
	fi

# =============================================================================
# Systemd Native Installation
# =============================================================================

INSTALL_DIR   := /usr/local/share/selfheal
BIN_DIR       := /usr/local/bin
SYSTEMD_DIR   := /etc/systemd/system
ENV_DIR       := /etc/default

install: agent-build
	@echo "Installing selfheal-agent..."
	sudo mkdir -p $(INSTALL_DIR)/probes
	sudo cp $(AGENT_BIN) $(BIN_DIR)/selfheal-agent
	sudo cp ebpf/probes/*.o $(INSTALL_DIR)/probes/
	sudo chmod 755 $(BIN_DIR)/selfheal-agent
	sudo systemctl daemon-reload
	@echo "✅ Installation complete. Start: sudo systemctl start selfheal-agent"

uninstall:
	-sudo systemctl stop selfheal-agent
	-sudo systemctl disable selfheal-agent
	sudo rm -f $(SYSTEMD_DIR)/selfheal-agent.service
	sudo rm -f $(BIN_DIR)/selfheal-agent
	sudo rm -rf $(INSTALL_DIR)
	sudo systemctl daemon-reload
	@echo "✅ Uninstalled"

systemd-start:
	sudo systemctl start selfheal-agent

systemd-stop:
	sudo systemctl stop selfheal-agent

systemd-status:
	sudo systemctl status selfheal-agent

systemd-logs:
	journalctl -u selfheal-agent -f

# =============================================================================
# Code Quality
# =============================================================================

fmt:
	$(GO) fmt ./...

lint:
	@which golangci-lint >/dev/null 2>&1 || (echo "Installing golangci-lint..." && \
	  go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run ./...

# =============================================================================
# Cleanup
# =============================================================================

clean:
	rm -rf bin/
	rm -f ebpf/probes/*.o ebpf/security/*.o
	rm -rf internal/ebpf/gen/
	@sudo rm -rf $(BPF_PIN_PATH) 2>/dev/null || true
	@echo "✅ Cleaned"

# =============================================================================
# Help
# =============================================================================

help:
	@echo ""
	@echo "SelfHeal-CP — Makefile Targets"
	@echo "================================"
	@echo ""
	@echo "  Build:"
	@echo "    make all              Build all components (default)"
	@echo "    make bpf              Compile all eBPF probes"
	@echo "    make bpf-core         Compile core probes only"
	@echo "    make bpf-security     Compile security probes only"
	@echo "    make bpf-skeleton     Generate BTF skeletons (CO-RE)"
	@echo "    make proto            Generate protobuf Go bindings"
	@echo "    make agent-build      Build eBPF agent binary"
	@echo "    make analyzer-build   Build heuristics engine"
	@echo "    make controller-build Build Kubernetes controller"
	@echo "    make observer-build   Build standalone observer (dev)"
	@echo "    make tui-build        Build terminal UI"
	@echo ""
	@echo "  Run:"
	@echo "    make run-agent        Run agent (root required)"
	@echo "    make run-agent-k8s    Run agent in k8s mode + security"
	@echo "    make run-observer     Run standalone observer"
	@echo "    make run-tui          Run TUI with live BPF"
	@echo "    make run-tui-demo     Run TUI demo (no root)"
	@echo ""
	@echo "  Dev:"
	@echo "    make dev-up           Start NATS + Prometheus + Grafana"
	@echo "    make dev-down         Stop dev stack"
	@echo "    make dev-logs         Tail dev stack logs"
	@echo ""
	@echo "  Test:"
	@echo "    make test             Run unit tests"
	@echo "    make test-integration Run integration tests"
	@echo "    make test-e2e         Run end-to-end tests"
	@echo ""
	@echo "  Kubernetes:"
	@echo "    make k8s-deploy       Deploy to minikube/cluster"
	@echo "    make k8s-undeploy     Remove from cluster"
	@echo "    make k8s-dashboard    Port-forward Grafana"
	@echo ""
	@echo "  Other:"
	@echo "    make clean            Remove build artifacts"
	@echo "    make fmt              Format Go code"
	@echo "    make lint             Run linter"
	@echo "    make help             Show this help"
	@echo ""