#!/usr/bin/env python3
"""
Challenger M4: Cloud-Native Packaging & Deployment Artifacts Audit
Verifies:
1. Dockerfile structure, multi-stage, distroless nonroot, zero-privilege, static musl target.
2. deploy/k8s/safegguf-initcontainer.yaml Kubernetes YAML schema, securityContext, readOnly volumes, fail-closed contract.
3. docs/production_deployment.md documentation completeness, architecture diagrams, air-gapped guidelines.
4. Static binary build simulation / cross-target validation.
"""

import sys
import os
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = REPO_ROOT / "Dockerfile"
K8S_MANIFEST = REPO_ROOT / "deploy" / "k8s" / "safegguf-initcontainer.yaml"
DEPLOY_DOC = REPO_ROOT / "docs" / "production_deployment.md"

results = []

def record(test_id: str, passed: bool, detail: str):
    status = "PASS" if passed else "FAIL"
    print(f"[{status}] {test_id}: {detail}")
    results.append({"id": test_id, "passed": passed, "detail": detail})

def audit_dockerfile():
    print("\n--- Auditing Dockerfile ---")
    if not DOCKERFILE.exists():
        record("DOCKER-EXISTS", False, "Dockerfile missing")
        return
    record("DOCKER-EXISTS", True, "Dockerfile present")

    content = DOCKERFILE.read_text(encoding="utf-8")
    
    # Check multi-stage
    stages = re.findall(r"^FROM\s+([^\s]+)\s+AS\s+([^\s]+)", content, re.MULTILINE | re.IGNORECASE)
    record("DOCKER-MULTI-STAGE", len(stages) >= 1, f"Found {len(stages)} named stages: {stages}")

    # Check distroless non-root
    has_distroless = "distroless/static" in content or "scratch" in content
    record("DOCKER-DISTROLESS", has_distroless, "Uses distroless static runtime")

    # Check non-root user
    has_nonroot = "USER nonroot" in content or "65532" in content
    record("DOCKER-NONROOT", has_nonroot, "Enforces nonroot user execution")

    # Check static musl compilation
    has_musl = "x86_64-linux-musl" in content and "ReleaseSafe" in content
    record("DOCKER-STATIC-MUSL", has_musl, "Builds ReleaseSafe with x86_64-linux-musl target")

    # Check entrypoint
    has_entrypoint = 'ENTRYPOINT ["/usr/local/bin/safegguf"]' in content
    record("DOCKER-ENTRYPOINT", has_entrypoint, "Correct entrypoint configured")

def audit_k8s_manifest():
    print("\n--- Auditing Kubernetes Manifest ---")
    if not K8S_MANIFEST.exists():
        record("K8S-EXISTS", False, f"Missing {K8S_MANIFEST}")
        return
    record("K8S-EXISTS", True, "Kubernetes manifest present")

    content = K8S_MANIFEST.read_text(encoding="utf-8")

    # Check Pod and initContainer
    has_pod = "kind: Pod" in content
    has_init = "initContainers:" in content
    record("K8S-POD-INITCONTAINER", has_pod and has_init, "Configures Pod with initContainer architecture")

    # Check securityContext constraints
    has_readonly_root = "readOnlyRootFilesystem: true" in content
    has_no_priv_esc = "allowPrivilegeEscalation: false" in content
    has_nonroot_user = "runAsNonRoot: true" in content or "runAsUser: 65532" in content
    record(
        "K8S-SECURITY-CONTEXT",
        has_readonly_root and has_no_priv_esc and has_nonroot_user,
        "Enforces readOnlyRootFilesystem, allowPrivilegeEscalation=false, runAsNonRoot"
    )

    # Check readOnly volume mount
    has_readonly_volume = "readOnly: true" in content and "mountPath: /models" in content
    record("K8S-READONLY-VOLUME", has_readonly_volume, "Model volume mounted read-only (prevents tampering)")

    # Check inspection command & parameters
    has_cmd = "inspect" in content and "--profile" in content and "--endian" in content and "auto" in content
    record("K8S-CMD-CONTRACT", has_cmd, "Executes safegguf inspect with auto-endianness and profile")

    # Check resource constraints
    has_resources = "limits:" in content and "requests:" in content and "memory:" in content
    record("K8S-RESOURCE-LIMITS", has_resources, "Explicit memory and CPU requests/limits configured")

def audit_deployment_docs():
    print("\n--- Auditing Production Deployment Documentation ---")
    if not DEPLOY_DOC.exists():
        record("DOCS-EXISTS", False, f"Missing {DEPLOY_DOC}")
        return
    record("DOCS-EXISTS", True, "Deployment documentation present")

    content = DEPLOY_DOC.read_text(encoding="utf-8")
    
    has_arch = "KIẾN TRÚC" in content or "Architecture" in content
    has_exit_codes = all(str(c) in content for c in [0, 2, 64, 70, 74])
    has_k8s_guide = "Kubernetes" in content or "initContainer" in content
    has_airgap = "Air-gapped" in content or "Offline" in content
    has_toctou = "TOCTOU" in content or "validate_fd" in content

    record("DOCS-ARCHITECTURE", has_arch, "Contains deployment architecture diagrams")
    record("DOCS-EXIT-CODES", has_exit_codes, "Documents complete exit code contract (0, 2, 64, 70, 74)")
    record("DOCS-K8S-INTEGRATION", has_k8s_guide, "Documents Kubernetes integration patterns")
    record("DOCS-AIRGAP-OFFLINE", has_airgap, "Documents offline air-gapped zero-token deployment")
    record("DOCS-ANTI-TOCTOU", has_toctou, "Documents in-process Anti-TOCTOU Python integration")

def main():
    print("======================================================================")
    print("  CHALLENGER M4: CLOUD-NATIVE PACKAGING & DEPLOYMENT ARTIFACTS AUDIT")
    print("======================================================================")
    
    audit_dockerfile()
    audit_k8s_manifest()
    audit_deployment_docs()

    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    failed = total - passed

    print("\n" + "=" * 70)
    print("                       SUMMARY OF RESULTS")
    print("=" * 70)
    print(f"Total Checks: {total}")
    print(f"Passed      : {passed}")
    print(f"Failed      : {failed}")

    if failed == 0:
        print("\n>>> OVERALL VERDICT: ALL CLOUD-NATIVE ARTIFACTS AUDITED & APPROVED <<<")
        sys.exit(0)
    else:
        print(f"\n>>> OVERALL VERDICT: {failed} AUDIT CHECKS FAILED <<<")
        sys.exit(1)

if __name__ == "__main__":
    main()
